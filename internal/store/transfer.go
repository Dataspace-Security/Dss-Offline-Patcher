package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const transferSchema = `
CREATE TABLE IF NOT EXISTS transfer_receipts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, file TEXT NOT NULL, file_sha256 TEXT NOT NULL, size INTEGER NOT NULL,
  adapter TEXT NOT NULL, sent_at TEXT NOT NULL, received_at TEXT NOT NULL, key_id TEXT NOT NULL, signature_ok INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS receipts_sha ON transfer_receipts(file_sha256);
`

type TransferReceipt struct {
	ID          int64  `json:"id"`
	File        string `json:"file"`
	FileSHA256  string `json:"file_sha256"`
	Size        int64  `json:"size"`
	Adapter     string `json:"adapter"`
	SentAt      string `json:"sent_at"`
	ReceivedAt  string `json:"received_at"`
	KeyID       string `json:"key_id"`
	SignatureOK bool   `json:"signature_ok"`
}

func (s *Store) RecordReceipt(ctx context.Context, r TransferReceipt) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		r.ReceivedAt = s.now()
		if _, err := tx.Exec(`INSERT INTO transfer_receipts(file,file_sha256,size,adapter,sent_at,received_at,key_id,signature_ok) VALUES(?,?,?,?,?,?,?,?)`,
			r.File, r.FileSHA256, r.Size, r.Adapter, r.SentAt, r.ReceivedAt, r.KeyID, boolInt(r.SignatureOK)); err != nil {
			return err
		}
		return s.audit(tx, Ev{Actor: "system:intake", Action: "transfer.receipt", ObjectType: "receipt", ObjectID: r.File, Failure: !r.SignatureOK,
			Details: map[string]any{"file_sha256": r.FileSHA256, "size": r.Size, "adapter": r.Adapter, "sent_at": r.SentAt, "signature_ok": r.SignatureOK, "key_id": r.KeyID}})
	})
}

// Reconciliation compares sender receipts with bundles that actually arrived.
type Reconciliation struct {
	Matched              []TransferReceipt `json:"matched"`
	ReceiptWithoutBundle []TransferReceipt `json:"receipt_without_bundle"` // sent, never arrived (or substituted)
	BundleWithoutReceipt []Bundle          `json:"bundle_without_receipt"` // arrived with no (valid) receipt
	UnsignedReceipts     int               `json:"unsigned_or_invalid_receipts"`
}

func (s *Store) Reconcile(ctx context.Context) (Reconciliation, error) {
	rec := Reconciliation{Matched: []TransferReceipt{}, ReceiptWithoutBundle: []TransferReceipt{}, BundleWithoutReceipt: []Bundle{}}
	rows, err := s.db.QueryContext(ctx, `SELECT id,file,file_sha256,size,adapter,sent_at,received_at,key_id,signature_ok FROM transfer_receipts ORDER BY id`)
	if err != nil {
		return rec, err
	}
	var rs []TransferReceipt
	for rows.Next() {
		var r TransferReceipt
		var ok int
		if err := rows.Scan(&r.ID, &r.File, &r.FileSHA256, &r.Size, &r.Adapter, &r.SentAt, &r.ReceivedAt, &r.KeyID, &ok); err != nil {
			rows.Close()
			return rec, err
		}
		r.SignatureOK = ok == 1
		rs = append(rs, r)
	}
	rows.Close()
	bundles, err := s.ListBundles(ctx)
	if err != nil {
		return rec, err
	}
	arrived := map[string]bool{}
	for _, b := range bundles {
		arrived[b.FileSHA256] = true
	}
	receipted := map[string]bool{}
	for _, r := range rs {
		if !r.SignatureOK {
			rec.UnsignedReceipts++
		}
		if strings.HasSuffix(r.File, ".trust.json") {
			continue // trust documents are tracked by trust.updated / trust.rejected audit events
		}
		if arrived[r.FileSHA256] {
			rec.Matched = append(rec.Matched, r)
		} else {
			rec.ReceiptWithoutBundle = append(rec.ReceiptWithoutBundle, r)
		}
		if r.SignatureOK {
			receipted[r.FileSHA256] = true
		}
	}
	for _, b := range bundles {
		if !receipted[b.FileSHA256] {
			rec.BundleWithoutReceipt = append(rec.BundleWithoutReceipt, b)
		}
	}
	return rec, nil
}

// IntakeVolume reports bundles and bytes received since t (rate limiting).
func (s *Store) IntakeVolume(ctx context.Context, since time.Time) (count int, bytes int64, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(file_size),0) FROM bundles WHERE received_at >= ?`, since.UTC().Format(time.RFC3339Nano)).Scan(&count, &bytes)
	return
}

// SaveTrust stores the latest verified trust document (signed form).
func (s *Store) SaveTrust(ctx context.Context, signedJSON string, seq int64, doc any) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for k, v := range map[string]string{"trust_doc": signedJSON, "trust_seq": fmt.Sprint(seq)} {
			if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v); err != nil {
				return err
			}
		}
		return s.audit(tx, Ev{Actor: "system:intake", Action: "trust.updated", ObjectType: "trust", ObjectID: fmt.Sprint(seq), Details: map[string]any{"document": doc}})
	})
}

// RevokeKeyContent revokes (or rejects, if not yet approved) every package
// delivered in a bundle signed by keyID — compromise response.
func (s *Store) RevokeKeyContent(ctx context.Context, keyID string) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.package_id, p.state FROM packages p JOIN bundles b ON b.bundle_id=p.bundle_id AND b.state='validated'
		WHERE b.key_id=? AND p.state IN ('quarantined','approved')`, keyID)
	if err != nil {
		return 0, err
	}
	type ps struct{ id, state string }
	var list []ps
	for rows.Next() {
		var x ps
		rows.Scan(&x.id, &x.state)
		list = append(list, x)
	}
	rows.Close()
	reason := "signing key " + keyID + " revoked as compromised"
	for _, x := range list {
		action := "revoke"
		if x.state == "quarantined" {
			action = "reject"
		}
		if _, err := s.SetPackageState(ctx, "system:trust", x.id, action, reason, nil); err != nil {
			return 0, err
		}
	}
	return len(list), nil
}
