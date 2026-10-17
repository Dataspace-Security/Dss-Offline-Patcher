//go:build darwin

package agent

import (
	"context"
	"os/exec"
	"time"
)

func readPower(ctx context.Context) (PowerStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/pmset", "-g", "batt").Output()
	if err != nil {
		return PowerStatus{}, err
	}
	return parsePmsetBatt(string(out)), nil
}
