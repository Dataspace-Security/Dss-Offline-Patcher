package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const windowsSchema = `
CREATE TABLE IF NOT EXISTS maintenance_windows(
  window_id TEXT PRIMARY KEY, name TEXT NOT NULL, groups TEXT NOT NULL, days TEXT NOT NULL,
  start TEXT NOT NULL, end_time TEXT NOT NULL, timezone TEXT NOT NULL, allow_reboot INTEGER NOT NULL,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL);
`

// MaintenanceWindow lets endpoint groups receive installs (and optionally
// reboots) only at agreed times, in the window's own time zone.
type MaintenanceWindow struct {
	WindowID    string   `json:"window_id"`
	Name        string   `json:"name"`
	Groups      []string `json:"groups"` // "all" = every endpoint
	Days        []string `json:"days"`   // mon..sun
	Start       string   `json:"start"`  // HH:MM local to Timezone
	End         string   `json:"end"`
	Timezone    string   `json:"timezone"` // IANA, e.g. Europe/London
	AllowReboot bool     `json:"allow_reboot"`
	CreatedBy   string   `json:"created_by"`
	CreatedAt   string   `json:"created_at"`
}

var weekdays = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// Open reports whether t falls inside the window. Windows may cross
// midnight (e.g. 22:00–04:00 belongs to the day it starts on).
func (w MaintenanceWindow) Open(t time.Time) bool {
	loc, err := time.LoadLocation(w.Timezone)
	if err != nil {
		return false
	}
	lt := t.In(loc)
	cur := lt.Format("15:04")
	day := weekdays[lt.Weekday()]
	prev := weekdays[(int(lt.Weekday())+6)%7]
	if w.Start <= w.End {
		return slices.Contains(w.Days, day) && cur >= w.Start && cur < w.End
	}
	return (slices.Contains(w.Days, day) && cur >= w.Start) || (slices.Contains(w.Days, prev) && cur < w.End)
}

func (w MaintenanceWindow) applies(groups []string) bool {
	for _, g := range w.Groups {
		if g == "all" || slices.Contains(groups, g) {
			return true
		}
	}
	return false
}

func listWindows(ctx context.Context, q querier) ([]MaintenanceWindow, error) {
	rows, err := q.QueryContext(ctx, `SELECT window_id,name,groups,days,start,end_time,timezone,allow_reboot,created_by,created_at FROM maintenance_windows ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MaintenanceWindow{}
	for rows.Next() {
		var w MaintenanceWindow
		var g, d string
		var ar int
		if err := rows.Scan(&w.WindowID, &w.Name, &g, &d, &w.Start, &w.End, &w.Timezone, &ar, &w.CreatedBy, &w.CreatedAt); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(g), &w.Groups)
		json.Unmarshal([]byte(d), &w.Days)
		w.AllowReboot = ar == 1
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) ListWindows(ctx context.Context) ([]MaintenanceWindow, error) {
	return listWindows(ctx, s.db)
}

// windowState: whether the endpoint has any windows, and whether one is open
// now (and allows reboots).
type windowState struct{ has, open, reboot bool }

func endpointWindows(all []MaintenanceWindow, groups []string, now time.Time) windowState {
	var ws windowState
	for _, w := range all {
		if !w.applies(groups) {
			continue
		}
		ws.has = true
		if w.Open(now) {
			ws.open = true
			if w.AllowReboot {
				ws.reboot = true
			}
		}
	}
	return ws
}

func (s *Store) CreateWindow(ctx context.Context, actor string, w MaintenanceWindow) (MaintenanceWindow, error) {
	var errs []string
	w.Name = strings.TrimSpace(w.Name)
	if w.Name == "" {
		errs = append(errs, "name required")
	}
	w.Groups = cleanGroups(w.Groups)
	if len(w.Groups) == 0 {
		errs = append(errs, "at least one group required (or \"all\")")
	}
	var days []string
	for _, d := range w.Days {
		d = strings.ToLower(strings.TrimSpace(d))
		if len(d) > 3 {
			d = d[:3]
		}
		if !slices.Contains(weekdays, d) {
			errs = append(errs, fmt.Sprintf("invalid day %q", d))
		} else if !slices.Contains(days, d) {
			days = append(days, d)
		}
	}
	w.Days = days
	if len(days) == 0 {
		errs = append(errs, "at least one day required")
	}
	if !hhmm.MatchString(w.Start) || !hhmm.MatchString(w.End) || w.Start == w.End {
		errs = append(errs, "start and end must be different HH:MM times")
	}
	if w.Timezone == "" {
		w.Timezone = "UTC"
	}
	if _, err := time.LoadLocation(w.Timezone); err != nil {
		errs = append(errs, "unknown timezone "+w.Timezone)
	}
	if len(errs) > 0 {
		return w, Errf(ErrInvalid, "%s", strings.Join(errs, "; "))
	}
	w.WindowID = NewID("w-")
	w.CreatedBy = actor
	w.CreatedAt = s.now()
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO maintenance_windows(window_id,name,groups,days,start,end_time,timezone,allow_reboot,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			w.WindowID, w.Name, mustJSON(w.Groups), mustJSON(w.Days), w.Start, w.End, w.Timezone, boolInt(w.AllowReboot), actor, w.CreatedAt); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: actor, Action: "window.created", ObjectType: "maintenance_window", ObjectID: w.WindowID,
			Details: map[string]any{"name": w.Name, "groups": w.Groups, "days": w.Days, "start": w.Start, "end": w.End, "timezone": w.Timezone, "allow_reboot": w.AllowReboot}})
	})
	return w, err
}

func (s *Store) DeleteWindow(ctx context.Context, actor, id, reason string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		err := tx.QueryRow(`SELECT name FROM maintenance_windows WHERE window_id=?`, id).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			return Errf(ErrNotFound, "window %s", id)
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM maintenance_windows WHERE window_id=?`, id); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: actor, Action: "window.deleted", ObjectType: "maintenance_window", ObjectID: id, Details: map[string]any{"name": name, "reason": reason}})
	})
}
