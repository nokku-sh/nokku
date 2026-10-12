package sshd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	agentRequestType = "auth-agent-req@openssh.com"
	agentChannelType = "auth-agent@openssh.com"
)

func (sess *session) agentRequest(req *ssh.Request) bool {
	if sess.handled {
		_ = req.Reply(false, nil)
		return false
	}
	if !sess.server.policy.Load().AllowAgentForwarding || !certExt(sess.conn, "permit-agent-forwarding") {
		_ = req.Reply(false, nil)
		return false
	}
	if sess.agentLn != nil {
		_ = req.Reply(true, nil)
		return false
	}
	ln, sock, err := newAgentSock(sess.sysUser)
	if err != nil {
		slog.Debug("create agent socket", "error", err)
		_ = req.Reply(false, nil)
		return false
	}
	sess.agentLn = ln
	sess.agentSock = sock
	_ = req.Reply(true, nil)
	return true
}

// The MkdirTemp dir is root-owned and 0700, so both dir and socket get chowned to the session user.
func newAgentSock(sysUser *account) (ln net.Listener, sock string, err error) {
	dir, err := os.MkdirTemp("", "auth-agent")
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if err != nil {
			if ln != nil {
				_ = ln.Close()
			}
			_ = os.RemoveAll(dir)
		}
	}()
	sock = filepath.Join(dir, "listener.sock")
	var lc net.ListenConfig
	if ln, err = lc.Listen(context.Background(), "unix", sock); err != nil {
		return nil, "", err
	}
	if os.Geteuid() != 0 {
		return ln, sock, nil
	}
	uid, gid := int(sysUser.UID), int(sysUser.GID)
	// The socket goes first, while the dir is still root-only. A user owning the dir could swap in a symlink.
	if err = os.Lchown(sock, uid, gid); err != nil {
		return nil, "", fmt.Errorf("chown agent socket: %w", err)
	}
	if err = os.Chmod(sock, 0o600); err != nil {
		return nil, "", fmt.Errorf("chmod agent socket: %w", err)
	}
	if err = os.Chown(dir, uid, gid); err != nil {
		return nil, "", fmt.Errorf("chown agent socket dir: %w", err)
	}
	return ln, sock, nil
}

func (sess *session) serveAgent() {
	defer os.RemoveAll(filepath.Dir(sess.agentSock))
	stop := context.AfterFunc(sess.ctx, func() { _ = sess.agentLn.Close() })
	defer stop()
	for {
		c, err := sess.agentLn.Accept()
		if err != nil {
			return
		}
		if !sess.st.acquireChannel() {
			_ = c.Close()
			continue
		}
		go func() {
			defer sess.st.releaseChannel()
			sess.relayAgentConn(c)
		}()
	}
}

func (sess *session) relayAgentConn(c net.Conn) {
	defer c.Close()
	ch, reqs, err := sess.conn.OpenChannel(agentChannelType, nil)
	if err != nil {
		return
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)

	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(c, ch)
		if u, ok := c.(*net.UnixConn); ok {
			_ = u.CloseWrite()
		}
	})
	wg.Go(func() {
		_, _ = io.Copy(ch, c)
		_ = ch.CloseWrite()
	})
	wg.Wait()
}
