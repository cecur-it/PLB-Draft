//go:build linux

// errow-tui bridge: transparent relay between Errow's Python backend and the Bubble Tea TUI sidecar that forwards
// metadata-only records of every IPC frame to Fluent Bit (Forward protocol, tag errow.tui_events).
//
// Traces: CONTRACT §2 (ERROW_TUI_PORT 24225), §3/§8.4 (errow.tui_events), §15 (tui_events); upstream
// errow/interface/tui/{sidecar.py,internal/app/client.go}. Installed in place of errow/bin/errow-tui; the real binary is
// kept next to it as errow-tui.real. Frames are never altered and payload bodies are never forwarded.
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const usage = `errow-tui bridge (stdlib only)

Runs the real TUI (errow-tui.real) behind a frame-preserving relay and forwards metadata-only records
(direction, frame type, request id, size) to Fluent Bit. Started by Errow exactly like errow-tui; the inherited
socketpair (errow_TUI_FD) or the Windows-style loopback pair (errow_TUI_ADDR + errow_TUI_TOKEN) is the upstream side.

Environment:
  ERROW_TUI_REAL          real TUI binary (default: errow-tui.real beside this executable)
  ERROW_TUI_FORWARD_ADDR  Fluent Bit forward input host:port (default fluent-bit:24225; "off" disables)
  ERROW_TUI_FORWARD_TAG   tag suffix appended by Fluent Bit's Tag_Prefix errow.tui_events. (default bridge)
  ERROW_TUI_EVENTS_FILE   optional NDJSON mirror of the same records (default: none)
  ERROW_RUN_ID            run name stamped on every record (default: empty)

Flags: --help, --version`

const version = "1.0.0"

type config struct {
	realBin     string
	realArgs    []string
	forwardAddr string
	tag         string
	eventsFile  string
	run         string
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--help", "-h":
			fmt.Println(usage)
			return
		case "--version":
			fmt.Println(version)
			return
		}
	}

	cfg, err := loadConfig(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "errow-tui bridge:", err)
		os.Exit(70)
	}
	upstream, err := connectUpstream()
	if err != nil {
		fmt.Fprintln(os.Stderr, "errow-tui bridge:", err)
		os.Exit(70)
	}
	os.Exit(runBridge(cfg, upstream))
}

func loadConfig(args []string, getenv func(string) string) (config, error) {
	cfg := config{
		realBin:     getenv("ERROW_TUI_REAL"),
		realArgs:    args,
		forwardAddr: getenv("ERROW_TUI_FORWARD_ADDR"),
		tag:         getenv("ERROW_TUI_FORWARD_TAG"),
		eventsFile:  getenv("ERROW_TUI_EVENTS_FILE"),
		run:         getenv("ERROW_RUN_ID"),
	}
	if cfg.realBin == "" {
		self, err := os.Executable()
		if err != nil {
			return cfg, fmt.Errorf("locate own executable: %w", err)
		}
		cfg.realBin = filepath.Join(filepath.Dir(self), "errow-tui.real")
	}
	if _, err := os.Stat(cfg.realBin); err != nil {
		return cfg, fmt.Errorf("real TUI binary: %w", err)
	}
	if cfg.forwardAddr == "" {
		cfg.forwardAddr = "fluent-bit:24225"
	}
	if strings.EqualFold(cfg.forwardAddr, "off") {
		cfg.forwardAddr = ""
	} else if _, _, err := net.SplitHostPort(cfg.forwardAddr); err != nil {
		return cfg, fmt.Errorf("ERROW_TUI_FORWARD_ADDR %q: %w", cfg.forwardAddr, err)
	}
	if cfg.tag == "" {
		cfg.tag = "bridge"
	}
	return cfg, nil
}

// connectUpstream opens the private channel prepared by the Python parent (see upstream client.go).
func connectUpstream() (net.Conn, error) {
	if fdValue := os.Getenv("errow_TUI_FD"); fdValue != "" {
		fd, err := strconv.ParseUint(fdValue, 10, 31)
		if err != nil {
			return nil, fmt.Errorf("invalid errow_TUI_FD: %w", err)
		}
		file := os.NewFile(uintptr(fd), "errow-tui-upstream")
		if file == nil {
			return nil, fmt.Errorf("invalid errow_TUI_FD %d", fd)
		}
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("open inherited TUI connection: %w", err)
		}
		return conn, nil
	}
	address, token := os.Getenv("errow_TUI_ADDR"), os.Getenv("errow_TUI_TOKEN")
	if address == "" || token == "" {
		return nil, errors.New("errow_TUI_FD or errow_TUI_ADDR and errow_TUI_TOKEN are required")
	}
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to TUI backend: %w", err)
	}
	if _, err := conn.Write([]byte(token)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("authenticate to TUI backend: %w", err)
	}
	return conn, nil
}

// runBridge starts the real TUI on a private socketpair, relays frames and returns the TUI's exit code.
func runBridge(cfg config, upstream net.Conn) int {
	defer upstream.Close()

	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "errow-tui bridge: socketpair:", err)
		return 70
	}
	parentFile := os.NewFile(uintptr(pair[0]), "bridge-parent")
	childFile := os.NewFile(uintptr(pair[1]), "bridge-child")
	downstream, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		_ = childFile.Close()
		fmt.Fprintln(os.Stderr, "errow-tui bridge: downstream:", err)
		return 70
	}
	defer downstream.Close()

	host, _ := os.Hostname()
	events := newEventSink(cfg, host)
	defer events.close()

	cmd := exec.Command(cfg.realBin, cfg.realArgs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{childFile}
	cmd.Env = childEnv(os.Environ())
	if err := cmd.Start(); err != nil {
		_ = childFile.Close()
		fmt.Fprintln(os.Stderr, "errow-tui bridge: start real TUI:", err)
		return 70
	}
	_ = childFile.Close()
	events.lifecycle("bridge_start", nil)

	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range signals {
			_ = cmd.Process.Signal(sig)
		}
	}()

	done := make(chan struct{}, 2)
	go func() { relay("backend_to_tui", upstream, downstream, events); done <- struct{}{} }()
	go func() { relay("tui_to_backend", downstream, upstream, events); done <- struct{}{} }()

	waitErr := cmd.Wait()
	signal.Stop(signals)
	close(signals)
	_ = downstream.Close()
	_ = upstream.Close()
	<-done

	code := exitCode(waitErr)
	events.lifecycle("tui_exit", []field{{"exit_code", code}})
	return code
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return exitErr.ExitCode()
	}
	return 70
}

// childEnv hands the real TUI the private socketpair as fd 3 and drops the upstream (Python) channel variables.
func childEnv(environ []string) []string {
	out := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case "errow_TUI_FD", "errow_TUI_ADDR", "errow_TUI_TOKEN":
			continue
		}
		out = append(out, kv)
	}
	return append(out, "errow_TUI_FD=3")
}
