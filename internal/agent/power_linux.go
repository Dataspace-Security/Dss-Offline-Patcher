//go:build linux

package agent

import "context"

func readPower(ctx context.Context) (PowerStatus, error) {
	return linuxPower("/sys/class/power_supply")
}
