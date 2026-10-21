//go:build windows

package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"offpatch/internal/manifest"
)

// installArchive runs the installer of an archive package (kind msi or exe
// with an archive block, agents 0.10.0+): the payload (already SHA-256
// verified by the agent) is extracted into a private run folder (SYSTEM
// and Administrators only) with the archive rules, every file is checked
// against the signed manifest's list, the EXE entry's Authenticode
// signature and signer are verified, and the entry runs from its own
// folder (setup.exe finds setup.ini and its .msi there). The folder is
// removed afterwards.
func (w *Windows) installArchive(ctx context.Context, p manifest.Package, file string) Result {
	dir, err := w.exeRunDir(p.PackageID)
	if err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "could not prepare a private folder for the installer: " + err.Error()}
	}
	defer os.RemoveAll(dir)
	tree, tmp := filepath.Join(dir, "a"), filepath.Join(dir, "t")
	for _, d := range []string{tree, tmp} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return Result{State: "failed", ExitCode: -1, Detail: "could not prepare a private folder for the installer: " + err.Error()}
		}
	}
	if err := extractArchive(p, file, tree); err != nil {
		return archiveFailure(err)
	}
	entry := archiveEntry(p, tree)
	switch p.Kind {
	case "msi":
		sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
		logPath := w.msiLog(p, "")
		code, res := runInstaller(ctx, filepath.Join(sys, "msiexec.exe"), "/i", entry, "/qn", "/norestart", "/l*v", logPath)
		if res != nil {
			return withMSILog(*res, logPath)
		}
		return withMSILog(classifyInstall("msi", code), logPath)
	case manifest.KindExe:
		args, err := exeArgs(p.Exe)
		if err != nil {
			return Result{State: "failed", ExitCode: -1, Detail: "exe package refused: " + err.Error()}
		}
		if err := signatureCheck(entry, p.Exe.Signer, winVerifyTrust); err != nil {
			return sigFailure(err)
		}
		code, res := runInstallerCmd(ctx, filepath.Base(entry), func(ctx context.Context) *exec.Cmd {
			cmd := exeCommand(ctx, entry, buildCmdLine(entry, args), tmp)
			cmd.Dir = filepath.Dir(entry)
			return cmd
		})
		if res != nil {
			return withBurnLog(*res, p.Exe, tmp)
		}
		return withBurnLog(classifyExe(p.Exe, code, false), p.Exe, tmp)
	}
	return Result{State: "failed", ExitCode: -1, Detail: "archive packages of kind " + p.Kind + " are not supported"}
}
