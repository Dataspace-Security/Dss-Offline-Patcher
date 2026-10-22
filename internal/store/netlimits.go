package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Network limits: how many machines may download installers at once,
// across the whole fleet (Policy.MaxDownloadsTotal) and per site
// (Policy.MaxDownloadsPerSite, SiteMaxDownloads per named site). They apply
// on top of each deployment's max_concurrent, to every deployment together,
// so a fleet-wide rollout cannot saturate the bank's WAN links. Rollbacks
// download nothing and are not limited. Endpoints without a site only count
// against the fleet-wide limit.
//
// A machine is downloading while a target of an active install deployment
// is "downloading", or was just handed out (pending/failed/deferred with a
// fresh lease, leaseFor) and has not reported yet.

const inflightDownloads = `SELECT COUNT(DISTINCT t.endpoint_id) FROM targets t
	JOIN deployments d ON d.deployment_id=t.deployment_id`

const inflightWhere = ` WHERE t.endpoint_id != ? AND d.state='active' AND d.operation='install'
	AND (t.state='downloading' OR (t.state IN ('pending','failed','deferred') AND t.leased_until > ?))`

// SiteDownloadLimit is the per-site limit for site (0 = none).
func (p Policy) SiteDownloadLimit(site string) int {
	if site == "" {
		return 0
	}
	if n, ok := p.SiteMaxDownloads[site]; ok {
		return n
	}
	return p.MaxDownloadsPerSite
}

// downloadSlotBusy returns why endpointID (at site) must wait before it
// starts a download, or "" when it may start now.
func (s *Store) downloadSlotBusy(ctx context.Context, tx *sql.Tx, endpointID, site, now string) (string, error) {
	if n := s.Policy.MaxDownloadsTotal; n > 0 {
		var busy int
		if err := tx.QueryRowContext(ctx, inflightDownloads+inflightWhere, endpointID, now).Scan(&busy); err != nil {
			return "", err
		}
		if busy >= n {
			return fmt.Sprintf("waiting: %d machines are downloading (network limit %d at once)", busy, n), nil
		}
	}
	if n := s.Policy.SiteDownloadLimit(site); n > 0 {
		var busy int
		if err := tx.QueryRowContext(ctx, inflightDownloads+` JOIN endpoints e ON e.endpoint_id=t.endpoint_id`+inflightWhere+` AND e.site=?`,
			endpointID, now, site).Scan(&busy); err != nil {
			return "", err
		}
		if busy >= n {
			return fmt.Sprintf("waiting: %d machines at site %s are downloading (site limit %d at once)", busy, site, n), nil
		}
	}
	return "", nil
}

// isNetworkWait: detail was set by downloadSlotBusy.
func isNetworkWait(detail string) bool {
	return strings.HasPrefix(detail, "waiting: ") && strings.Contains(detail, " limit ")
}
