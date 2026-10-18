package server

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"offpatch/internal/trust"
)

// Version is set at build time: -ldflags "-X offpatch/internal/server.Version=1.2.3".
var Version = "0.1.0"

var startedAt = time.Now().UTC()

type keyInfo struct {
	KeyID   string   `json:"key_id"`
	Sources []string `json:"sources"`
	Status  string   `json:"status"` // active | retired
}

func dirStats(root string) (files int, bytes int64) {
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, e := d.Info(); e == nil {
				files++
				bytes += fi.Size()
			}
		}
		return nil
	})
	return
}

// system reports the management server's configuration and health for the
// console's Server page. Secrets (tokens, keys, client secrets) are never
// included.
func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := s.cfg
	icfg, _ := c.IntakeConfig()

	keys := []keyInfo{}
	trustSeq, _ := s.store.GetMeta(ctx, "trust_seq")
	if raw, _ := s.store.GetMeta(ctx, "trust_doc"); raw != "" && icfg.RootPub != nil {
		if signed, err := trust.Parse([]byte(raw)); err == nil {
			if doc, err := trust.Verify(signed, icfg.RootPub); err == nil {
				for _, k := range doc.Keys {
					keys = append(keys, keyInfo{KeyID: k.KeyID, Sources: k.Sources, Status: k.Status})
				}
			}
		}
	}
	if len(keys) == 0 {
		for id, k := range icfg.Keys {
			st := "active"
			if k.Retired {
				st = "retired"
			}
			keys = append(keys, keyInfo{KeyID: id, Sources: k.Sources, Status: st})
		}
	}

	waiting := 0
	if ents, err := os.ReadDir(icfg.Inbox); err == nil {
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".pmb") {
				waiting++
			}
		}
	}
	lastBundle := ""
	if bs, err := s.store.ListBundles(ctx); err == nil && len(bs) > 0 {
		lastBundle = bs[0].ReceivedAt
	}
	repoFiles, repoBytes := dirStats(filepath.Join(c.DataDir, "repository"))
	var dbBytes int64
	for _, f := range []string{"pm.db", "pm.db-wal"} {
		if fi, err := os.Stat(filepath.Join(c.DataDir, f)); err == nil {
			dbBytes += fi.Size()
		}
	}
	chain, _ := s.store.AuditChainStatus(ctx)
	exported, _ := s.store.GetMeta(ctx, "audit_exported_seq")
	alerts, _ := s.store.ListAlerts(ctx, true)
	deadlines := map[string]string{}
	for k, v := range c.PatchDeadlines {
		deadlines[k] = v.String()
	}
	out := map[string]any{
		"version":        Version,
		"go_version":     runtime.Version(),
		"platform":       runtime.GOOS + "/" + runtime.GOARCH,
		"started_at":     startedAt.Format(time.RFC3339),
		"uptime_seconds": int(time.Since(startedAt).Seconds()),
		"listen":         c.Listen,
		"security": map[string]any{
			"tls": c.TLSCert != "", "mtls_agents": c.PKIDir != "", "insecure_http": c.InsecureHTTP,
			"sso": c.OIDC != nil, "require_mfa": c.RequireMFA,
		},
		"policy": map[string]any{
			"approval_policy": c.ApprovalPolicy, "separation_of_duties": c.SeparationOfDuties, "patch_deadlines": deadlines,
		},
		"trust": map[string]any{"root_key_configured": icfg.RootPub != nil, "trust_document_sequence": trustSeq, "bundle_keys": keys},
		"intake": map[string]any{
			"interval": c.IntakeInterval.String(), "inbox": icfg.Inbox, "bundles_waiting": waiting, "last_bundle_received_at": lastBundle,
			"max_bundles_per_hour": c.IntakeMaxBundlesPerHour, "max_bytes_per_hour": c.IntakeMaxBytesPerHour,
			"content_scanner": len(c.ScanCommand) > 0, "max_bundle_bytes": c.MaxBundleBytes,
		},
		"storage": map[string]any{
			"data_dir": c.DataDir, "database_bytes": dbBytes, "repository_objects": repoFiles, "repository_bytes": repoBytes,
		},
		"audit": map[string]any{
			"chain_ok": chain.OK, "events": chain.Count, "export_dir": c.AuditExportDir, "exported_to_seq": exported,
			"checkpoint_interval": c.AuditCheckpointEvery.String(), "retention": c.AuditRetention.String(),
		},
		"agents": map[string]any{
			"checkin_interval_seconds": c.CheckinIntervalSeconds, "offline_after": c.OfflineAfter.String(),
			"stale_inventory_after": c.StaleInventoryAfter.String(), "download_rate_kbps": c.DownloadRateKbps,
			"lost_after_install": c.LostAfterInstall.String(), "preinstall_min_free_disk_mb": c.Preinstall.MinFreeDiskMB, "preinstall_min_battery_pct": c.Preinstall.policyFor("windows").MinBatteryPct,
		},
		"open_alerts": len(alerts),
	}
	writeJSON(w, 200, out)
}

func (s *Server) acquisition(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	srcs, hist, err := s.store.Acquisition(r.Context(), limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"sources": srcs, "history": hist, "stale_after_hours": int(s.store.AcqStale().Hours())})
}
