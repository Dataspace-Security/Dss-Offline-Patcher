// pmagent is the endpoint agent. It only ever talks to the configured
// management server; it has no internet or Windows Update fallback.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"offpatch/internal/agent"
)

const usage = `pmagent — offpatch endpoint agent

  pmagent enroll -server <url> -token <enrollment token> -pubkey <bundle.pub>[,more.pub] [-ca ca.pem] [-root-pubkey root.pub]
                 [-state-dir dir] [-platform windows|linux|macos|sim] [-hostname h -build n -sim-fail KB1,KB2 -sim-reboot]
  pmagent run    [-state-dir dir] [-once]
  pmagent service install|uninstall [-state-dir dir]     (Windows service, systemd unit or launchd daemon)
`

func defaultStateDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "offpatch")
	case "linux":
		return "/var/lib/offpatch"
	case "darwin":
		return "/Library/Application Support/offpatch"
	}
	return "agent-state"
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if isService() {
		runService(log)
		return
	}
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		err = enroll(os.Args[2:])
	case "run":
		err = run(os.Args[2:], log)
	case "service":
		err = serviceCmd(os.Args[2:])
	case "version":
		fmt.Println(agent.Version)
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func enroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "management server URL (internal network)")
	token := fs.String("token", "", "one-time enrollment token")
	pubs := fs.String("pubkey", "", "bundle signing public key file(s), comma-separated")
	rootPub := fs.String("root-pubkey", "", "root public key (enables signed key rotation/revocation updates)")
	ca := fs.String("ca", "", "CA certificate to pin for https")
	dir := fs.String("state-dir", defaultStateDir(), "agent state directory")
	plat := fs.String("platform", map[string]string{"windows": "windows", "linux": "linux", "darwin": "macos"}[runtime.GOOS], "windows | linux | macos | sim")
	host := fs.String("hostname", "", "sim: hostname")
	build := fs.Int("build", 19045, "sim: Windows build number")
	simFail := fs.String("sim-fail", "", "sim: KBs/product codes whose install fails")
	simReboot := fs.Bool("sim-reboot", false, "sim: installs require a reboot")
	fs.Parse(args)
	if *server == "" || *token == "" || *pubs == "" {
		return fmt.Errorf("-server, -token and -pubkey are required")
	}
	var keys []string
	for _, p := range strings.Split(*pubs, ",") {
		b, err := os.ReadFile(strings.TrimSpace(p))
		if err != nil {
			return err
		}
		keys = append(keys, string(b))
	}
	var sim *agent.SimConfig
	if *plat == "sim" {
		h := *host
		if h == "" {
			h, _ = os.Hostname()
			h += "-sim"
		}
		sim = &agent.SimConfig{Hostname: h, Build: *build, Arch: "x64", Reboot: *simReboot}
		if *simFail != "" {
			sim.FailKBs = strings.Split(*simFail, ",")
		}
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	p, err := agent.PlatformFor(&agent.State{Platform: *plat, Sim: sim}, *dir)
	if err != nil {
		return err
	}
	var rootPEM string
	if *rootPub != "" {
		b, err := os.ReadFile(*rootPub)
		if err != nil {
			return err
		}
		rootPEM = string(b)
	}
	st, err := agent.Enroll(*server, *token, *ca, *dir, keys, rootPEM, p, *plat, sim)
	if err != nil {
		return err
	}
	fmt.Printf("enrolled as %s (platform %s); state in %s\n", st.EndpointID, *plat, *dir)
	return nil
}

func run(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dir := fs.String("state-dir", defaultStateDir(), "agent state directory")
	once := fs.Bool("once", false, "run a single check-in cycle and exit")
	fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := runAgent(ctx, *dir, *once, log)
	if errors.Is(err, agent.ErrRestart) {
		os.Exit(3) // non-zero: service managers restart us with the new binary
	}
	return err
}

func runAgent(ctx context.Context, dir string, once bool, log *slog.Logger) error {
	st, err := agent.LoadState(dir)
	if err != nil {
		return err
	}
	p, err := agent.PlatformFor(st, dir)
	if err != nil {
		return err
	}
	a, err := agent.New(st, dir, p, log.With("endpoint", st.EndpointID))
	if err != nil {
		return err
	}
	log.Info("pmagent starting", "version", agent.Version, "server", st.ServerURL, "platform", p.Name())
	return a.Run(ctx, once)
}
