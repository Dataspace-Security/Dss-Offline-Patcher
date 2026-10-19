package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"offpatch/internal/server"
)

// startConsoleProxy opens the console_proxy listener (plain HTTP for a
// reverse proxy that terminates TLS; browser surface only) and serves it in
// the background. The address is bound here, so a taken port stops the
// start-up with a clear error. failed receives a later serve error.
func startConsoleProxy(cfg *server.Config, h *server.Server, log *slog.Logger, failed chan<- error) (*http.Server, error) {
	cp := cfg.ConsoleProxy
	if cp == nil {
		return nil, nil
	}
	ln, err := net.Listen("tcp", cp.Listen)
	if err != nil {
		return nil, fmt.Errorf("console_proxy.listen %s: %w", cp.Listen, err)
	}
	srv := &http.Server{
		Handler:           h.ConsoleProxyHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		// Plain HTTP: no TLS configuration, so no client certificate is ever
		// requested here (agents use the main listener).
	}
	log.Info("console reverse-proxy listener (plain HTTP; TLS at the proxy; console only, no agent API)",
		"addr", cp.Listen, "trusted_proxies", strings.Join(cp.TrustedProxies, ","))
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			failed <- fmt.Errorf("console_proxy listener %s: %w", cp.Listen, err)
		}
	}()
	return srv, nil
}
