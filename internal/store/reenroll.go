package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

// genericSerials are placeholder BIOS serial numbers many machines share;
// they never identify one machine. Empty, whitespace-only and all-zero
// (or all-F) serials are generic too (genericSerial).
var genericSerials = map[string]bool{
	"": true, "0": true, "none": true, "n/a": true, "na": true, "null": true, "unknown": true, "invalid": true,
	"default string": true, "to be filled by o.e.m.": true, "to be filled by oem": true, "o.e.m.": true, "oem": true,
	"system serial number": true, "chassis serial number": true, "base board serial number": true, "serial number": true,
	"not specified": true, "not applicable": true, "not available": true, "default": true,
	"0123456789": true, "123456789": true, "1234567890": true, "12345678": true, "00000000": true, "ffffffff": true,
}

// genericSerial reports whether a BIOS serial number is a placeholder:
// listed in genericSerials (case and surrounding spaces ignored), or made
// only of zeros, or only of F's, once spaces, dashes, dots and colons are
// removed.
func genericSerial(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if genericSerials[s] {
		return true
	}
	bare := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '.', ':', '_', '\t':
			return -1
		}
		return r
	}, s)
	return bare == "" || strings.Trim(bare, "0") == "" || strings.Trim(bare, "f") == ""
}

// sameMachine: two hardware reports describe one physical (or virtual)
// machine: the same non-generic serial number. The MAC address stands in
// only when neither report has a real serial number (both generic or
// empty); a real serial that differs, or one real and one generic, is
// never the same machine.
func sameMachine(a, b Hardware) bool {
	ga, gb := genericSerial(a.SerialNumber), genericSerial(b.SerialNumber)
	if !ga && !gb {
		return strings.EqualFold(strings.TrimSpace(a.SerialNumber), strings.TrimSpace(b.SerialNumber))
	}
	if !ga || !gb {
		return false
	}
	ma, mb := strings.ToLower(strings.TrimSpace(a.MACAddress)), strings.ToLower(strings.TrimSpace(b.MACAddress))
	return ma != "" && ma == mb
}

// retireReplaced retires older endpoint records of the machine that just
// checked in as endpointID: re-running the enrollment command on a PC
// creates a new endpoint, and the old record would otherwise stay "in
// progress" in deployments and duplicate the machine in every list. Its
// open targets become not_applicable; the new record gets its own targets.
//
// A check-in's hardware report is the endpoint's own claim, so an old
// record is retired only when all of these hold: it is in the same site
// (enrollment site) as the new record; it has the same host name (case
// ignored); it is the same machine (sameMachine: the same real serial
// number, or the same MAC when both serials are placeholders); it was
// enrolled no later than the new record; and it has not checked in since
// the new record was enrolled (old last_seen <= new enrolled_at), i.e. it
// is the stale one. A live machine, or one in another site, is never
// retired by another endpoint's claims.
func (s *Store) retireReplaced(ctx context.Context, tx *sql.Tx, endpointID, hostname string, hw Hardware) error {
	var site, enrolledAt string
	if err := tx.QueryRowContext(ctx, `SELECT site, enrolled_at FROM endpoints WHERE endpoint_id=?`, endpointID).Scan(&site, &enrolledAt); err != nil {
		return err
	}
	newEnrolled := parseTime(enrolledAt)
	rows, err := tx.QueryContext(ctx, `SELECT endpoint_id, hardware, enrolled_at, last_seen FROM endpoints
		WHERE endpoint_id != ? AND retired_at = '' AND site = ? AND lower(hostname) = lower(?)`,
		endpointID, site, hostname)
	if err != nil {
		return err
	}
	var old []string
	for rows.Next() {
		var id, raw, enr, seen string
		if err := rows.Scan(&id, &raw, &enr, &seen); err != nil {
			rows.Close()
			return err
		}
		if parseTime(enr).After(newEnrolled) || parseTime(seen).After(newEnrolled) {
			continue // enrolled later, or still checking in: not the stale record
		}
		var h Hardware
		if raw != "" && json.Unmarshal([]byte(raw), &h) == nil && sameMachine(h, hw) {
			old = append(old, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range old {
		if _, err := s.retireEndpointTx(ctx, tx, "system:reenroll", id, "re-enrolled as "+endpointID); err != nil {
			return err
		}
	}
	return nil
}
