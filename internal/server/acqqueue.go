package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"offpatch/internal/acqrequest"
)

// Direct hand-off of acquisition requests ("acquisition_requests_dir"): only
// for an acquisition host on the same machine, or an outbound folder the
// organisation approved. Production with separate hosts leaves it unset and
// the operator carries the downloaded file (strict one-way transfer).

// queuedRequest is the POST /api/acquisition-requests response: the request
// document plus where it was queued ("" = not queued; carry the file).
type queuedRequest struct {
	*acqrequest.Request
	QueuedTo string `json:"queued_to"`
}

// queueAcqRequest writes req as <dir>/<request_id>.json atomically (temp
// file, fsync, rename; mode 0640). The file is exactly the request document.
func queueAcqRequest(dir string, req *acqrequest.Request) (err error) {
	// req passed Validate: RequestID is a safe file name.
	b, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(dir, ".tmp-"+req.RequestID+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	final := filepath.Join(dir, req.RequestID+".json")
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	// Make the rename durable (best effort: not supported on every OS).
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// CheckAcquisitionRequestsDir reports whether pmserver can create files in
// dir (a startup warning only: the console falls back to the download).
func CheckAcquisitionRequestsDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	f, err := os.CreateTemp(dir, ".tmp-writable-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}
