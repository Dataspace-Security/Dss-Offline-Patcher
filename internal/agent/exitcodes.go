package agent

import "fmt"

// Exit codes documented by Microsoft for wusa.exe / msiexec.exe. HRESULTs
// are compared as uint32 (Go reports them as large positive ints).
const (
	exitOK                 = 0
	exitRebootRequired     = 3010       // ERROR_SUCCESS_REBOOT_REQUIRED
	exitRebootInitiated    = 1641       // ERROR_SUCCESS_REBOOT_INITIATED
	exitHRRebootRequired   = 0x80070BC2 // HRESULT_FROM_WIN32(3010), returned by wusa
	exitWusaAlready        = 0x00240006 // WU_S_ALREADY_INSTALLED
	exitWusaAlreadyRemoved = 0x00240007 // WU_S_ALREADY_UNINSTALLED
	exitWusaNotApplic      = 0x80240017 // WU_E_NOT_APPLICABLE
	exitCBSNotApplic       = 0x800F081E // CBS_E_NOT_APPLICABLE
	exitMsiUnknownProduct  = 1605       // ERROR_UNKNOWN_PRODUCT: not installed
	exitMsiBusy            = 1618       // ERROR_INSTALL_ALREADY_RUNNING
	exitMsiOtherVersion    = 1638       // ERROR_PRODUCT_VERSION
	exitWUInstallNotAllow  = 0x80240016 // WU_E_INSTALL_NOT_ALLOWED: another install is running
	exitWUServiceStop      = 0x8024001E // WU_E_SERVICE_STOP: servicing stack shutting down
	exitCBSBusy            = 0x800F0902 // CBS_E_BUSY: another servicing operation in progress
)

// retryLater is the detail prefix for installer-busy exits. The state stays
// "failed" (the protocol has no transient-failure state); the server retries
// within the deployment's max_retries.
const retryLater = "retry later: installer busy"

func installerBusy(u uint32) bool {
	switch u {
	case exitMsiBusy, exitWUInstallNotAllow, exitWUServiceStop, exitCBSBusy:
		return true
	}
	return false
}

// classifyInstall maps a wusa/msiexec exit code for an install to a result
// state that the agent/server protocol already knows.
func classifyInstall(kind string, code int) Result {
	u := uint32(code)
	switch {
	case u == exitOK:
		return Result{State: "installed", ExitCode: code, Detail: kind + " installed"}
	case u == exitRebootRequired || u == exitRebootInitiated || u == exitHRRebootRequired:
		return Result{State: "pending_reboot", ExitCode: code, Detail: "installed; reboot required"}
	case kind == "msu" && u == exitWusaAlready:
		return Result{State: "installed", ExitCode: code, Detail: "already installed"}
	case kind == "msu" && (u == exitWusaNotApplic || u == exitCBSNotApplic):
		return Result{State: "not_applicable", ExitCode: code, Detail: fmt.Sprintf("wusa: update not applicable to this computer (0x%08X)", u)}
	case installerBusy(u):
		return Result{State: "failed", ExitCode: code, Detail: fmt.Sprintf("%s (another installation or servicing operation is in progress, 0x%08X)", retryLater, u)}
	case kind == "msi" && u == exitMsiOtherVersion:
		return Result{State: "failed", ExitCode: code, Detail: "another version of this product is already installed"}
	}
	return Result{State: "failed", ExitCode: code, Detail: fmt.Sprintf("installer exit code %d (0x%08X)", code, u)}
}

// classifyUninstall maps an exit code for a rollback (wusa /uninstall,
// msiexec /x). "installed" means the rollback operation completed.
func classifyUninstall(kind string, code int) Result {
	u := uint32(code)
	switch {
	case u == exitOK:
		return Result{State: "installed", ExitCode: code, Detail: kind + " uninstalled"}
	case u == exitRebootRequired || u == exitRebootInitiated || u == exitHRRebootRequired:
		return Result{State: "pending_reboot", ExitCode: code, Detail: "uninstalled; reboot required"}
	case kind == "msu" && u == exitWusaAlreadyRemoved, kind == "msi" && u == exitMsiUnknownProduct:
		return Result{State: "installed", ExitCode: code, Detail: "not installed; nothing to remove"}
	case installerBusy(u):
		return Result{State: "failed", ExitCode: code, Detail: fmt.Sprintf("%s (another installation or servicing operation is in progress, 0x%08X)", retryLater, u)}
	}
	return Result{State: "failed", ExitCode: code, Detail: fmt.Sprintf("uninstaller exit code %d (0x%08X)", code, u)}
}
