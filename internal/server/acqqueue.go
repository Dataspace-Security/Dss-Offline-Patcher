package server

import (
	"encoding/json"
	"fmt"
	"os"

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
func queueAcqRequest(dir string, req *acqrequest.Request) error {
	// req passed Validate: RequestID is a safe file name.
	b, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return err
	}
	return writeQueued(dir, req.RequestID+".json", append(b, '\n'))
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
