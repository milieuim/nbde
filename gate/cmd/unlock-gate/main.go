// Command unlock-gate is the policy-gated Tang server (serve), its local
// emergency control (ctl), the running client's sender (send), and the
// approver's tool (approve, deny). See docs/design.md §6.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/milieuim/nbde/gate/internal/gate"
)

const usage = `usage:
  unlock-gate serve --config <gate.json>
  unlock-gate ctl [--socket <path>] status|approve|deny|disarm --client <name> [--window <secs>] [--from <cidr>]...
  unlock-gate send --config <agent.json> heartbeat|arm|disarm
  unlock-gate approve --config <approver.json> [--window <secs>] [--from <cidr>]... [--yes]
  unlock-gate deny --config <approver.json> [--yes]
  unlock-gate agent-key <path>          create an agent key, print its public key
  unlock-gate agent-key --public <path> print the public key of an existing agent key
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "serve":
		err = serve(args)
	case "ctl":
		err = ctl(args)
	case "send":
		err = send(args)
	case "approve":
		err = approve(args, gate.TypApprove)
	case "deny":
		err = approve(args, gate.TypDeny)
	case "agent-key":
		err = agentKey(args)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "unlock-gate:", err)
		os.Exit(1)
	}
}

// listFlag collects repeated --from values.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	return fs
}

// parseInterspersed lets flags follow positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func serve(args []string) error {
	fs := newFlags("serve")
	configPath := fs.String("config", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := gate.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var notifier gate.Notifier = gate.LogNotifier{Log: log}
	if cfg.Telegram != nil {
		tg, err := gate.NewTelegram(cfg.Telegram, log)
		if err != nil {
			return err
		}
		notifier = multiNotifier{gate.LogNotifier{Log: log}, tg}
	}
	g, err := gate.New(cfg, notifier, log)
	if err != nil {
		return err
	}
	// Bind TCP first: if another gate holds the ports, fail before touching
	// its ctl socket.
	public, err := gate.Listen(cfg.PublicListen)
	if err != nil {
		return err
	}
	mesh, err := gate.Listen(cfg.MeshListen)
	if err != nil {
		return err
	}
	ln, err := gate.ListenCtl(cfg.CtlSocket)
	if err != nil {
		return fmt.Errorf("ctl socket: %w", err)
	}
	defer os.Remove(cfg.CtlSocket)

	errs := make(chan error, 3)
	go func() { errs <- g.ServeCtl(ln) }()
	go func() { errs <- gate.Serve(public, g.PublicHandler()) }()
	go func() { errs <- gate.Serve(mesh, g.MeshHandler()) }()
	stop := make(chan struct{})
	go g.RunHeartbeatMonitor(stop)
	log.Info("unlock-gate started", "gate", cfg.GateID, "public", cfg.PublicListen, "mesh", cfg.MeshListen)
	if err := sdNotify("READY=1"); err != nil {
		log.Warn("sd_notify failed", "err", err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err = <-errs:
	case s := <-sigs:
		log.Info("stopping", "signal", s.String())
	}
	close(stop)
	_ = ln.Close()
	return err
}

type multiNotifier []gate.Notifier

func (m multiNotifier) Notify(e gate.Event) {
	for _, n := range m {
		n.Notify(e)
	}
}

func ctl(args []string) error {
	fs := newFlags("ctl")
	socket := fs.String("socket", "/run/unlock-gate/ctl.sock", "")
	client := fs.String("client", "", "")
	window := fs.Int64("window", 0, "")
	var from listFlag
	fs.Var(&from, "from", "")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || *client == "" {
		return errors.New("ctl needs one command and --client")
	}
	resp, err := gate.CallCtl(*socket, gate.CtlRequest{Cmd: pos[0], Client: *client, Window: *window, From: from})
	if err != nil {
		return fmt.Errorf("ctl: %w (ctl requires root)", err)
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	if resp.Status != nil {
		printStatus(resp.Status.Gate, *resp.Status)
		if len(resp.Status.Thumbprints) > 0 {
			fmt.Printf("  thp (pin these in clevis): %s\n", strings.Join(resp.Status.Thumbprints, " "))
		}
	} else {
		fmt.Println("ok")
	}
	return nil
}

func send(args []string) error {
	fs := newFlags("send")
	configPath := fs.String("config", "/etc/unlock-gate/agent.json", "")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("send needs one of heartbeat, arm, disarm")
	}
	typ := pos[0]
	if typ != gate.TypHeartbeat && typ != gate.TypArm && typ != gate.TypDisarm {
		return fmt.Errorf("unknown message %q", typ)
	}
	cfg, err := gate.LoadAgentConfig(*configPath)
	if err != nil {
		return err
	}
	results, err := gate.SendAgent(cfg, typ)
	if err != nil {
		return err
	}
	printResults(typ, results)
	// An arm that fewer than Threshold gates hold cannot unlock; the caller
	// (eihort-reboot) MUST NOT reboot then.
	if typ == gate.TypArm && gate.Succeeded(results) < gate.Threshold {
		return fmt.Errorf("arm accepted by %d gates, need %d", gate.Succeeded(results), gate.Threshold)
	}
	return nil
}

func printResults(what string, results []gate.Result) {
	for _, r := range results {
		if r.Err != nil {
			fmt.Printf("%-6s %s: %v\n", r.Gate, what, r.Err)
		} else {
			fmt.Printf("%-6s %s: accepted\n", r.Gate, what)
		}
	}
}

func approve(args []string, typ string) error {
	fs := newFlags(typ)
	configPath := fs.String("config", defaultApproverConfig(), "")
	window := fs.Int64("window", int64(gate.DefaultWindow/time.Second), "")
	yes := fs.Bool("yes", false, "")
	var from listFlag
	fs.Var(&from, "from", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := gate.LoadApproverConfig(*configPath)
	if err != nil {
		return err
	}

	statuses, results := gate.FetchStatus(cfg.Gates, cfg.Client)
	for _, r := range results {
		if r.Err != nil {
			fmt.Printf("== %s: status unavailable: %v\n", r.Gate, r.Err)
			continue
		}
		printStatus(r.Gate, statuses[r.Gate])
	}

	claims, err := gate.NewApproval(cfg, typ, time.Duration(*window)*time.Second, from)
	if err != nil {
		return err
	}
	summary := fmt.Sprintf("%s %s on %s", typ, cfg.Client, strings.Join(claims.Gates, ","))
	if typ == gate.TypApprove {
		summary += fmt.Sprintf(" for %ds", claims.Window)
		if len(from) > 0 {
			summary += " from " + strings.Join(from, ",")
		}
	}
	if !*yes && !confirm(summary+"?") {
		return errors.New("cancelled")
	}

	message, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	signature, err := sshSign(cfg.KeyFile, message)
	if err != nil {
		return err
	}
	posted := gate.PostApproval(cfg.Gates, message, signature)
	printResults(typ, posted)
	if typ == gate.TypApprove && gate.Succeeded(posted) < gate.Threshold {
		return fmt.Errorf("approval accepted by %d gates, need %d", gate.Succeeded(posted), gate.Threshold)
	}
	return nil
}

// defaultApproverConfig prefers the user's config, then the system one
// written by the programs.unlock-approve NixOS module.
func defaultApproverConfig() string {
	if dir, err := os.UserConfigDir(); err == nil {
		path := filepath.Join(dir, "unlock-gate", "approver.json")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return "/etc/unlock-gate/approver.json"
}

func confirm(question string) bool {
	fmt.Printf("%s [y/N] ", question)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}

// sshSign runs ssh-keygen -Y sign, which talks to the security key (one
// touch). This runs on the approver's machine, never on a gate.
func sshSign(keyFile string, message []byte) (string, error) {
	dir, err := os.MkdirTemp("", "unlock-gate-approve-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	msgPath := filepath.Join(dir, "approval.json")
	if err := os.WriteFile(msgPath, message, 0o600); err != nil {
		return "", err
	}
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-q", "-f", keyFile, "-n", gate.SignatureNamespace, msgPath)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ssh-keygen -Y sign: %w", err)
	}
	sig, err := os.ReadFile(msgPath + ".sig")
	if err != nil {
		return "", err
	}
	return string(sig), nil
}

func printStatus(id string, st gate.Status) {
	fmt.Printf("== %s (%s), gate time %s\n", id, st.Client, st.Now.Format(time.RFC3339))
	if hb := st.Heartbeat; hb != nil {
		state := "ok"
		if hb.Lost {
			state = "LOST"
		}
		fmt.Printf("  heartbeat: %s, %s ago, boot %s\n", state, st.Now.Sub(hb.At).Round(time.Second), hb.BootID)
	} else {
		fmt.Println("  heartbeat: never seen since gate start")
	}
	if st.Arm != nil {
		fmt.Printf("  arm: expires in %s\n", st.Arm.Sub(st.Now).Round(time.Second))
	}
	if a := st.Approval; a != nil {
		fmt.Printf("  approval: expires in %s %s\n", a.Expires.Sub(st.Now).Round(time.Second), strings.Join(a.From, ","))
	}
	if len(st.Attempts) == 0 {
		fmt.Println("  no unlock attempts")
	}
	for _, a := range st.Attempts {
		result := "refused"
		if a.Released {
			result = "released"
		}
		fmt.Printf("  %s  %-40s %-8s %s\n", a.At.Format(time.RFC3339), a.Source, result, a.Reason)
	}
}

func agentKey(args []string) error {
	fs := newFlags("agent-key")
	public := fs.Bool("public", false, "")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("agent-key needs a path")
	}
	if *public {
		key, err := gate.ReadAgentKey(pos[0])
		if err != nil {
			return err
		}
		fmt.Println(base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
		return nil
	}
	pub, err := gate.CreateAgentKey(pos[0])
	if err != nil {
		return err
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(pub))
	return nil
}

// sdNotify tells systemd (Type=notify) that every listener is bound. It is
// a no-op outside systemd.
func sdNotify(state string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	if path[0] == '@' {
		path = "\x00" + path[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}
