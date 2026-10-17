//go:build !windows && !linux && !darwin

package main

import (
	"errors"
	"log/slog"
)

func isService() bool { return false }

func runService(*slog.Logger) {}

func serviceCmd([]string) error {
	return errors.New("service install is only supported on Windows; use `pmagent run` here")
}

func singleInstance() (release func(), err error) { return func() {}, nil }
