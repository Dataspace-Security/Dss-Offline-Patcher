package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

// genericSerials are placeholder BIOS serial numbers many machines share;
// they never identify one machine.
var genericSerials = map[string]bool{
	"": true, "0": true, "none": true, "n/a": true, "default string": true, "to be filled by o.e.m.": true,
	"system serial number": true, "not specified": true, "not applicable": true, "0123456789": true,
}

// sameMachine: two hardware reports describe one physical (or virtual)
// machine: the same non-generic serial number, or the same MAC address.
func sameMachine(a, b Hardware) bool {
	sa, sb := strings.ToLower(strings.TrimSpace(a.SerialNumber)), strings.ToLower(strings.TrimSpace(b.SerialNumber))
	if !genericSerials[sa] && sa == sb {
		return true
	}
	ma, mb := strings.ToLower(strings.TrimSpace(a.MACAddress)), strings.ToLower(strings.TrimSpace(b.MACAddress))
	return ma != "" && ma == mb
}

// retireReplaced retires older endpoint records of the machine that just
// checked in as endpointID: re-running the enrollment command on a PC
// creates a new endpoint, and the old record (same host name and the same
// serial number or MAC address) would otherwise stay "in progress" in
// deployments and duplicate the machine in every list. Its open targets
// become not_applicable; the new record gets its own targets.
func (s *Store) retireReplaced(ctx context.Context, tx *sql.Tx, endpointID, hostname string, hw Hardware) error {
	rows, err := tx.QueryContext(ctx, `SELECT endpoint_id, hardware FROM endpoints
		WHERE endpoint_id != ? AND retired_at = '' AND lower(hostname) = lower(?) AND enrolled_at <= (SELECT enrolled_at FROM endpoints WHERE endpoint_id=?)`,
		endpointID, hostname, endpointID)
	if err != nil {
		return err
	}
	var old []string
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
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
