// Package sshclient dials the daemon's sshd over a relay for web terminals.
package sshclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultWidth  = 80
	defaultHeight = 24
	chunkSize     = 32 * 1024
	// Matches the daemon's sshd, which answers keepalive@openssh.com.
	keepaliveInterval = 30 * time.Second
	sessionEnvVar     = "NOKKU_SESSION_ID"
)

// Config HostPrincipal is the daemon's target id.
type Config struct {
	HostPrincipal string
	Username      string
	Signer        ssh.Signer
	CAKey         ssh.PublicKey
	SessionID     string
	Width         uint32
	Height        uint32
}

// Terminal is safe to Resize concurrently with Write.
type Terminal struct {
	client *ssh.Client
	ch     ssh.Channel

	stdout chan []byte
	halt   chan struct{}
	done   chan struct{}

	closeOnce sync.Once
	doneOnce  sync.Once
}

// Stdout is closed when the terminal ends.
func (t *Terminal) Stdout() <-chan []byte { return t.stdout }

func (t *Terminal) Write(p []byte) (int, error) { return t.ch.Write(p) }

// Resize is fire and forget, like OpenSSH.
func (t *Terminal) Resize(width, height uint32) error {
	_, err := t.ch.SendRequest("window-change", false, ssh.Marshal(
		struct{ Columns, Rows, WidthPx, HeightPx uint32 }{width, height, 0, 0},
	))
	return err
}

func (t *Terminal) Close() {
	t.closeOnce.Do(func() {
		close(t.halt)
		_ = t.ch.Close()
		_ = t.client.Close()
	})
}

func (t *Terminal) finish() {
	t.doneOnce.Do(func() { close(t.done) })
}

// DialTerminal closes the transport when ctx ends, which wakes every blocked stage.
func DialTerminal(ctx context.Context, conn net.Conn, cfg Config) (*Terminal, error) {
	if cfg.Width == 0 {
		cfg.Width = defaultWidth
	}
	if cfg.Height == 0 {
		cfg.Height = defaultHeight
	}

	type result struct {
		term *Terminal
		err  error
	}
	res := make(chan result, 1)
	go func() {
		term, err := dial(conn, cfg)
		res <- result{term, err}
	}()
	select {
	case r := <-res:
		return r.term, r.err
	case <-ctx.Done():
		_ = conn.Close()
		r := <-res
		if r.term != nil {
			r.term.Close()
		}
		return nil, ctx.Err()
	}
}

func dial(conn net.Conn, cfg Config) (*Terminal, error) {
	caKey := cfg.CAKey
	config := &ssh.ClientConfig{
		User: cfg.Username,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(cfg.Signer)},
		HostKeyCallback: (&ssh.CertChecker{
			IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
				return bytes.Equal(auth.Marshal(), caKey.Marshal())
			},
		}).CheckHostKey,
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(
		conn,
		net.JoinHostPort(cfg.HostPrincipal, "22"),
		config,
	)
	if err != nil {
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(clientConn, chans, reqs)

	fail := func(stage string, err error) (*Terminal, error) {
		_ = client.Close()
		return nil, fmt.Errorf("%s: %w", stage, err)
	}

	ch, _, err := client.OpenChannel("session", nil)
	if err != nil {
		return fail("open session channel", err)
	}

	// env before pty-req: the daemon's recorder starts on pty-req and reads
	// the session id from the environment.
	env := struct{ Name, Value string }{sessionEnvVar, cfg.SessionID}
	if _, err = ch.SendRequest("env", true, ssh.Marshal(env)); err != nil {
		return fail("env request", err)
	}
	pty := struct {
		Term     string
		Columns  uint32
		Rows     uint32
		WidthPx  uint32
		HeightPx uint32
		Modes    []byte
	}{"xterm-256color", cfg.Width, cfg.Height, 0, 0, []byte{}}
	ok, err := ch.SendRequest("pty-req", true, ssh.Marshal(pty))
	if err != nil {
		return fail("pty request", err)
	}
	if !ok {
		return fail("pty request", errors.New("rejected by remote, missing permit-pty?"))
	}
	ok, err = ch.SendRequest("shell", true, nil)
	if err != nil {
		return fail("shell request", err)
	}
	if !ok {
		return fail("shell request", errors.New("rejected by remote"))
	}

	t := &Terminal{
		client: client,
		ch:     ch,
		stdout: make(chan []byte, 16),
		halt:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go t.pump()
	go t.keepalive()
	return t, nil
}

func (t *Terminal) pump() {
	defer close(t.stdout)
	defer t.finish()
	buf := make([]byte, chunkSize)
	for {
		n, err := t.ch.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			select {
			case t.stdout <- chunk:
			case <-t.halt:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// keepalive treats a failed keepalive@openssh.com as a dead relay or sshd.
func (t *Terminal) keepalive() {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.halt:
			return
		case <-t.done:
			return
		case <-ticker.C:
			if _, _, err := t.client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				t.Close()
				return
			}
		}
	}
}
