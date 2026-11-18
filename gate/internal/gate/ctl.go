package gate

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// CtlRequest is one line on the ctl socket (§6.8).
type CtlRequest struct {
	Cmd    string   `json:"cmd"`
	Client string   `json:"client"`
	Window int64    `json:"window,omitempty"`
	From   []string `json:"from,omitempty"`
}

// CtlResponse is the reply line.
type CtlResponse struct {
	OK     bool    `json:"ok"`
	Error  string  `json:"error,omitempty"`
	Status *Status `json:"status,omitempty"`
}

const (
	ctlMaxLine     = 4 << 10
	ctlIdleTimeout = 30 * time.Second
	DefaultWindow  = 300 * time.Second
)

// ListenCtl binds the ctl socket with mode 0600, replacing only a stale socket.
func ListenCtl(path string) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != os.ModeSocket {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		// Only a stale socket may be replaced, never a running gate's.
		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%s is in use by another process", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	old := syscall.Umask(0o177)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	return ln, err
}

// ServeCtl accepts ctl connections until the listener closes.
func (g *Gate) ServeCtl(ln *net.UnixListener) error {
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go g.handleCtl(conn)
	}
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}

func (g *Gate) handleCtl(conn *net.UnixConn) {
	defer conn.Close()
	uid, err := peerUID(conn)
	if err != nil || uid != 0 {
		g.log.Warn("ctl peer refused", "uid", uid, "err", err)
		return
	}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, ctlMaxLine), ctlMaxLine)
	enc := json.NewEncoder(conn)
	for {
		_ = conn.SetDeadline(time.Now().Add(ctlIdleTimeout))
		if !scanner.Scan() {
			return
		}
		var req CtlRequest
		resp := CtlResponse{OK: true}
		if err := decodeStrict(scanner.Bytes(), &req); err != nil {
			resp = CtlResponse{Error: "bad request: " + err.Error()}
		} else if st, err := g.runCtl(req); err != nil {
			resp = CtlResponse{Error: err.Error()}
		} else {
			resp.Status = st
		}
		if enc.Encode(resp) != nil {
			return
		}
	}
}

func (g *Gate) runCtl(req CtlRequest) (*Status, error) {
	switch req.Cmd {
	case "status":
		st, ok := g.Status(req.Client, true)
		if !ok {
			return nil, fmt.Errorf("unknown client %q", req.Client)
		}
		return &st, nil
	case "approve":
		window := DefaultWindow
		if req.Window != 0 {
			window = time.Duration(req.Window) * time.Second
		}
		from, err := parsePrefixes(req.From)
		if err != nil {
			return nil, err
		}
		return nil, g.Approve(req.Client, window, from, "ctl")
	case "deny":
		return nil, g.Deny(req.Client, "ctl")
	case "disarm":
		return nil, g.Disarm(req.Client, "ctl")
	}
	return nil, fmt.Errorf("unknown command %q", req.Cmd)
}

// CallCtl sends one request to a gate's ctl socket.
func CallCtl(path string, req CtlRequest) (*CtlResponse, error) {
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ctlIdleTimeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp CtlResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read ctl reply: %w", err)
	}
	return &resp, nil
}
