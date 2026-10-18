package main

// Disk retention for pmctl auto (the acquisition host runs unattended for
// years): old run directories with their bundles, downloaded files of
// packages sent long ago, and abandoned partial downloads are deleted.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runDirTimeFormat prefixes run directory names (runs/<time>-<random>).
const runDirTimeFormat = "20060102T150405Z"

func applyRetention(c *autoConfig, st autoState, runDir string, inUse map[string]bool, rep *autoReport) {
	now := autoNow()
	warn := func(err error) { rep.Warnings = append(rep.Warnings, "retention: "+err.Error()) }
	if c.KeepRunsDays > 0 {
		cutoff := now.Add(-time.Duration(c.KeepRunsDays) * 24 * time.Hour)
		pruneRuns(filepath.Join(c.WorkDir, "runs"), runDir, cutoff, warn)
	}
	if c.KeepDownloadsDays > 0 {
		cutoff := now.Add(-time.Duration(c.KeepDownloadsDays) * 24 * time.Hour)
		pruneDownloads(filepath.Join(c.WorkDir, "downloads"), st, inUse, cutoff, warn)
	}
	pruneOldVersions(filepath.Join(c.WorkDir, "downloads"), st, inUse, c.keepLastN, warn)
}

// pruneRuns deletes run directories older than cutoff (by the time in their
// name, else their modification time), except the current one.
func pruneRuns(runs, current string, cutoff time.Time, warn func(error)) {
	ents, err := os.ReadDir(runs)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			warn(err)
		}
		return
	}
	for _, e := range ents {
		p := filepath.Join(runs, e.Name())
		if !e.IsDir() || p == current {
			continue
		}
		t, err := time.Parse(runDirTimeFormat, strings.SplitN(e.Name(), "-", 2)[0])
		if err != nil {
			fi, ierr := e.Info()
			if ierr != nil {
				continue
			}
			t = fi.ModTime()
		}
		if t.Before(cutoff) {
			if err := os.RemoveAll(p); err != nil {
				warn(err)
			}
		}
	}
}

// pruneDownloads deletes the downloaded file of every package sent before
// cutoff (unless this run still uses it), and .part / unverified leftovers
// not touched since cutoff.
func pruneDownloads(dir string, st autoState, inUse map[string]bool, cutoff time.Time, warn func(error)) {
	for _, d := range st.Done {
		if d.File == "" || inUse[d.File] || d.File != filepath.Base(d.File) {
			continue
		}
		sent, err := time.Parse(time.RFC3339, d.SentAt)
		if err != nil || !sent.Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, d.File)); err != nil && !errors.Is(err, os.ErrNotExist) {
			warn(err)
		}
	}
	for _, sub := range []string{dir, filepath.Join(dir, ".unverified")} {
		ents, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !e.Type().IsRegular() || (sub == dir && !strings.HasSuffix(e.Name(), ".part")) {
				continue
			}
			fi, err := e.Info()
			if err != nil || !fi.ModTime().Before(cutoff) {
				continue
			}
			if err := os.Remove(filepath.Join(sub, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				warn(fmt.Errorf("%s: %w", e.Name(), err))
			}
		}
	}
}
