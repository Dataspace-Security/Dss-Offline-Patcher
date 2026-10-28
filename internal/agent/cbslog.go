package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// A failed wusa.exe (msu install or uninstall) says why only in the
// Component-Based Servicing log (CBS.log). The last cause lines of that log
// go into the failure detail, so the operator sees the servicing error in
// the console instead of a bare "installer exit code N (0x…)" — as
// withMSILog does for msiexec verbose logs.
//
// This file is cross-platform on purpose: only where CBS.log lives is
// Windows-specific (the caller in platform_windows.go passes the path in).
// The read/filter/append logic here needs no OS, so it is testable anywhere.

const (
	// cbsLogHeader labels the excerpt when it is appended to a failure
	// detail, like msiLogHeader for msiexec logs.
	cbsLogHeader = "\nCBS log (last lines):\n"
	// The tail fits within the 2000-char detail cap the server enforces.
	cbsLogTailChars = msiLogTailChars
)

// cbsCause matches the servicing-log lines that explain a failure: the
// error text CBS writes, the HRESULT it reports (e.g. 0x800F0068), and the
// operation markers that show where servicing stopped. The log's noise —
// the per-component [Start]/[End] Opack= chatter — does not match, so the
// filter drops it.
var cbsCause = regexp.MustCompile(`(?i)(error|fail|unable|incomplete|0x[0-9a-f]{8}|operation)`)

// cbsLogTail returns the last cause lines of the servicing log at path —
// at most msiLogTailLines, within cbsLogTailChars-len(cbsLogHeader) bytes
// (the budget shared with msiLogTail, so the appended detail stays under
// the 2000-char cap ReportTarget enforces). "" when the log is missing or
// holds nothing useful.
func cbsLogTail(path string) string {
	text := readLogTailText(path)
	if text == "" {
		return ""
	}
	var kept []string
	for _, l := range meaningfulLines(text) {
		if cbsCause.MatchString(l) {
			kept = append(kept, l)
		}
	}
	if len(kept) == 0 {
		return ""
	}
	return meaningfulTail(strings.Join(kept, "\n"), msiLogTailLines, cbsLogTailChars-len(cbsLogHeader))
}

// withCBSLog appends the tail of the servicing log to a failed wusa result.
// Success, "not applicable" and "installer busy" results are left alone:
// their log says nothing useful and the server recognises a busy repeat by
// its unchanged detail.
func withCBSLog(r Result, cbsLogPath string) Result {
	if r.State != "failed" || cbsLogPath == "" || strings.HasPrefix(r.Detail, retryLater) {
		return r
	}
	tail := cbsLogTail(cbsLogPath)
	if tail == "" {
		return r
	}
	r.Detail += cbsLogHeader + tail
	return r
}

// cbsLogPathFor returns this machine's servicing log path, or "" when it
// cannot be determined (no SystemRoot set, or no readable log) — callers
// pass "" through and the detail stays as-is.
func cbsLogPathFor() string {
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		return ""
	}
	p := filepath.Join(sysroot, "Logs", "CBS", "CBS.log")
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}
