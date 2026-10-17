//go:build !windows && !linux && !darwin

package agent

import (
	"context"
	"errors"
)

func readPower(ctx context.Context) (PowerStatus, error) {
	return PowerStatus{}, errors.New("power status not available on this OS")
}
