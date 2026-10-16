// Package auditexport periodically exports audit events off the server and
// writes Ed25519-signed checkpoints (seq + chain hash). Exported files are
// meant for write-once storage (WORM share, SIEM drop folder). Because the
// checkpoints are signed and held elsewhere, even an attacker who can
// rewrite the whole database chain is detected.
package auditexport

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// Checkpoint is one line of checkpoints.jsonl.
type Checkpoint struct {
	Seq       int64  `json:"seq"`
	Hash      string `json:"hash"`
	FromSeq   int64  `json:"from_seq"` // events exported in this batch: (from_seq, seq]
	File      string `json:"file"`
	FileSHA   string `json:"file_sha256"`
	CreatedAt string `json:"created_at"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"` // over the JSON of this struct with Signature=""
}

func (c Checkpoint) payload() []byte {
	c.Signature = ""
	b, _ := json.Marshal(c)
	return b
}

// LoadOrCreateKey returns the server's checkpoint signing key.
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if k, err := manifest.LoadPrivate(path); err == nil {
		return k, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	pub, priv, err := manifest.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, manifest.EncodePrivate(priv), 0o600); err != nil {
		return nil, err
	}
	return priv, os.WriteFile(strings.TrimSuffix(path, ".key")+".pub", manifest.EncodePublic(pub), 0o644)
}

type Exporter struct {
	Store *store.Store
	Dir   string
	Key   ed25519.PrivateKey
	Log   *slog.Logger
}

const metaKey = "audit_exported_seq"

// Export writes new events since the last export and a signed checkpoint.
// It returns the checkpoint (zero if nothing new).
func (x *Exporter) Export(ctx context.Context) (Checkpoint, error) {
	if err := os.MkdirAll(x.Dir, 0o750); err != nil {
		return Checkpoint{}, err
	}
	v, err := x.Store.GetMeta(ctx, metaKey)
	if err != nil {
		return Checkpoint{}, err
	}
	from, _ := strconv.ParseInt(v, 10, 64)
	// An export directory that is ahead of the database means the database was
	// restored from an older backup: never write overlapping evidence.
	if last := lastCheckpointSeq(x.Dir); last > from {
		return Checkpoint{}, fmt.Errorf("export directory %s already has checkpoints up to seq %d but the database has exported only to %d (restored from backup?) — point audit_export_dir at a new directory", x.Dir, last, from)
	}
	head, hash, err := x.Store.AuditHead(ctx)
	if err != nil || head <= from {
		return Checkpoint{}, err
	}
	evs, err := x.Store.AuditRange(ctx, from, head)
	if err != nil {
		return Checkpoint{}, err
	}
	name := fmt.Sprintf("audit-%012d-%012d.jsonl", from+1, head)
	tmp := filepath.Join(x.Dir, name+".part")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return Checkpoint{}, err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, e := range evs {
		if err := enc.Encode(e); err != nil {
			f.Close()
			return Checkpoint{}, err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return Checkpoint{}, err
	}
	f.Sync()
	f.Close()
	if err := os.Rename(tmp, filepath.Join(x.Dir, name)); err != nil {
		return Checkpoint{}, err
	}
	_, fsha, err := manifest.HashFile(filepath.Join(x.Dir, name))
	if err != nil {
		return Checkpoint{}, err
	}
	cp := Checkpoint{Seq: head, Hash: hash, FromSeq: from, File: name, FileSHA: fsha, CreatedAt: time.Now().UTC().Format(time.RFC3339),
		KeyID: manifest.KeyID(x.Key.Public().(ed25519.PublicKey))}
	cp.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(x.Key, cp.payload()))
	line, _ := json.Marshal(cp)
	cf, err := os.OpenFile(filepath.Join(x.Dir, "checkpoints.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return Checkpoint{}, err
	}
	_, err = cf.Write(append(line, '\n'))
	if serr := cf.Sync(); err == nil {
		err = serr
	}
	cf.Close()
	if err != nil {
		return Checkpoint{}, err
	}
	if err := x.Store.SetMeta(ctx, metaKey, strconv.FormatInt(head, 10)); err != nil {
		return Checkpoint{}, err
	}
	return cp, x.Store.Audit(ctx, store.Ev{Actor: "system:audit-export", Action: "audit.checkpoint", ObjectType: "audit", ObjectID: strconv.FormatInt(head, 10),
		Details: map[string]any{"from_seq": from, "seq": head, "hash": hash, "file": name, "file_sha256": fsha}})
}

// Run exports every interval and prunes per retention (0 = keep forever).
func (x *Exporter) Run(ctx context.Context, every time.Duration, retention time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		cp, err := x.Export(ctx)
		if err != nil {
			x.Log.Error("audit export failed", "err", err)
			x.Store.RaiseAlert(ctx, "critical", "audit_export_failed", "audit", "export", "audit export to "+x.Dir+" failed: "+err.Error())
		} else if cp.Seq > 0 && retention > 0 {
			if n, err := x.Store.PruneAudit(ctx, cp.Seq, time.Now().Add(-retention)); err != nil {
				x.Log.Error("audit prune failed", "err", err)
			} else if n > 0 {
				x.Log.Info("audit retention pruned exported events", "events", n)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Report is the result of an off-box verification.
type Report struct {
	OK          bool     `json:"ok"`
	Checkpoints int      `json:"checkpoints"`
	Events      int64    `json:"events"`
	LastSeq     int64    `json:"last_seq"`
	Problems    []string `json:"problems"`
}

// Verify checks an export directory on its own: checkpoint signatures, file
// hashes, event chain continuity across files, and that each checkpoint's
// hash is the hash of its last event. If st is non-nil it also checks that
// the live database still contains the checkpointed hashes (detects a
// rewritten database chain).
func Verify(ctx context.Context, dir string, pub ed25519.PublicKey, st *store.Store) (Report, error) {
	rep := Report{}
	b, err := os.ReadFile(filepath.Join(dir, "checkpoints.jsonl"))
	if err != nil {
		return rep, err
	}
	var cps []Checkpoint
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var c Checkpoint
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			rep.Problems = append(rep.Problems, "unparseable checkpoint line")
			continue
		}
		cps = append(cps, c)
	}
	sort.Slice(cps, func(i, j int) bool { return cps[i].Seq < cps[j].Seq })
	prevHash := ""
	var prevSeq int64
	for i, c := range cps {
		rep.Checkpoints++
		sig, _ := base64.StdEncoding.DecodeString(c.Signature)
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, c.payload(), sig) {
			rep.Problems = append(rep.Problems, fmt.Sprintf("checkpoint %d: bad signature", c.Seq))
			continue
		}
		if i > 0 && c.FromSeq != prevSeq {
			rep.Problems = append(rep.Problems, fmt.Sprintf("checkpoint %d: gap after %d", c.Seq, prevSeq))
		}
		_, fsha, err := manifest.HashFile(filepath.Join(dir, filepath.Base(c.File)))
		if err != nil || fsha != c.FileSHA {
			rep.Problems = append(rep.Problems, fmt.Sprintf("checkpoint %d: export file %s missing or modified", c.Seq, c.File))
			continue
		}
		evs, err := readEvents(filepath.Join(dir, filepath.Base(c.File)))
		if err != nil {
			rep.Problems = append(rep.Problems, err.Error())
			continue
		}
		for _, e := range evs {
			if prevHash != "" && e.PrevHash != prevHash {
				rep.Problems = append(rep.Problems, fmt.Sprintf("event %d: chain break", e.Seq))
			}
			if store.ChainHash(e.PrevHash, e) != e.Hash {
				rep.Problems = append(rep.Problems, fmt.Sprintf("event %d: hash mismatch", e.Seq))
			}
			prevHash = e.Hash
			rep.Events++
		}
		if len(evs) == 0 || evs[len(evs)-1].Seq != c.Seq || evs[len(evs)-1].Hash != c.Hash {
			rep.Problems = append(rep.Problems, fmt.Sprintf("checkpoint %d: does not match last exported event", c.Seq))
		}
		if st != nil {
			if h, err := st.AuditHashAt(ctx, c.Seq); err == nil && h != c.Hash {
				rep.Problems = append(rep.Problems, fmt.Sprintf("checkpoint %d: database event hash differs — database chain was rewritten", c.Seq))
			}
		}
		prevSeq = c.Seq
		rep.LastSeq = c.Seq
	}
	if st != nil {
		if cr, err := st.VerifyAudit(ctx); err == nil && !cr.OK {
			rep.Problems = append(rep.Problems, fmt.Sprintf("database chain: %s at %d", cr.Error, cr.FirstBadSeq))
		}
	}
	rep.OK = len(rep.Problems) == 0 && rep.Checkpoints > 0
	return rep, nil
}

func readEvents(path string) ([]store.AuditEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []store.AuditEvent
	dec := json.NewDecoder(f)
	for dec.More() {
		var e store.AuditEvent
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		out = append(out, e)
	}
	return out, nil
}

func lastCheckpointSeq(dir string) int64 {
	b, err := os.ReadFile(filepath.Join(dir, "checkpoints.jsonl"))
	if err != nil {
		return 0
	}
	var last int64
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var c Checkpoint
		if json.Unmarshal([]byte(line), &c) == nil && c.Seq > last {
			last = c.Seq
		}
	}
	return last
}
