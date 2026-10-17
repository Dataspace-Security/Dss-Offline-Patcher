package main

// Bundle sequence state. The isolated server accepts a bundle only if its
// sequence is above the last one it accepted for that source, so a sequence
// must never be reused or lowered. pmctl build and pmctl auto share the same
// state file per source (auto: acquire.json "sequence_state", default
// <work_dir>/sequence.json; build: -state, or -config acquire.json).
//
// A number is reserved (written) before the bundle is signed, under a lock:
// a build that fails afterwards leaves a gap, which the server accepts; two
// builds can never get the same number.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type pmctlState struct {
	Sequences map[string]int64 `json:"sequences"`
}

// readSeqState loads path; a missing file is empty state, an unreadable or
// unparseable one is an error (never silently restart at 1).
func readSeqState(path string) (pmctlState, error) {
	st := pmctlState{Sequences: map[string]int64{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("sequence state %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("sequence state %s is corrupt (%v); refusing to guess the next sequence: restore it, or fix the JSON by hand with a sequence above the last bundle sent", path, err)
	}
	if st.Sequences == nil {
		st.Sequences = map[string]int64{}
	}
	return st, nil
}

// reserveSequence returns the sequence for the next bundle of source and
// records it in path. explicit (pmctl build -seq) must be above the stored
// value; 0 means "next". The stored value only ever grows.
func reserveSequence(path, source string, explicit int64) (int64, error) {
	if explicit < 0 {
		return 0, fmt.Errorf("sequence must be positive (got %d)", explicit)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return 0, err
	}
	unlock, err := lockFile(path+".lock", 30*time.Second, 2*time.Minute)
	if err != nil {
		return 0, err
	}
	defer unlock()
	st, err := readSeqState(path)
	if err != nil {
		return 0, err
	}
	cur := st.Sequences[source]
	seq := cur + 1
	if explicit != 0 {
		if explicit <= cur {
			return 0, fmt.Errorf("-seq %d is not above the last sequence %d recorded for source %q in %s: the server would reject the bundle as a replay", explicit, cur, source, path)
		}
		seq = explicit
	}
	st.Sequences[source] = max(cur, seq)
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := writeFileAtomic(path, b, 0o600); err != nil {
		return 0, fmt.Errorf("sequence state %s: %w", path, err)
	}
	return seq, nil
}

// knownSequenceStates lists other places a sequence for this source may be
// recorded: the defaults of pmctl build and pmctl auto in the current
// directory, and the state named by ./acquire.json.
func knownSequenceStates() []string {
	cands := []string{".pmctl-state.json", "sequence.json", filepath.Join("work", "sequence.json")}
	if c, err := loadAutoConfig("acquire.json"); err == nil {
		cands = append(cands, c.SequenceState)
	}
	return cands
}

// sequenceStateWarnings explains a likely mistake before a manual build:
// path has no sequence for source, but another known state file does.
func sequenceStateWarnings(path, source string) []string {
	st, err := readSeqState(path)
	if err != nil || st.Sequences[source] != 0 {
		return nil
	}
	abs, _ := filepath.Abs(path)
	var out []string
	for _, p := range knownSequenceStates() {
		pa, _ := filepath.Abs(p)
		if pa == abs {
			continue
		}
		other, err := readSeqState(p)
		if err != nil || other.Sequences[source] == 0 {
			continue
		}
		out = append(out, fmt.Sprintf("%s has no sequence for source %q, but %s records %d: this bundle would get sequence 1 and the server would reject it as a replay; pass -state %s (or -config acquire.json)",
			path, source, p, other.Sequences[source], p))
	}
	return out
}
