package client

import (
	"cmp"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os/exec"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/daemon/internal/hostcerts"
	"github.com/nokku-sh/nokku/daemon/internal/state"
	"github.com/nokku-sh/nokku/daemon/internal/sysutil"
)

// A failed sync keeps the old access, a failed save keeps the new in memory.
func (c *Client) syncDaemon(ctx context.Context) error {
	c.syncing.Lock()
	defer c.syncing.Unlock()
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	// LDAP or SSSD can be slow, the sync still gets 5 of its 15 s.
	usersCtx, stop := context.WithTimeout(ctx, 10*time.Second)
	passwd, err := exec.CommandContext(usersCtx, "getent", "passwd").Output()
	stop()
	if err != nil {
		// Output keeps a cut last line from before a timeout.
		slog.Warn("list system users", "error", err)
		passwd = nil
	}
	res, err := c.ctl.SyncDaemon(ctx, &nokkuv1.SyncDaemonRequest{
		PrivateIps: c.sshEndpoints(ctx),
		Users:      login.Accounts(string(passwd)),
		Metadata:   sysutil.Metadata(),
	})
	if err != nil {
		return err
	}

	// The core hashes every answer, one without a hash is not from it.
	if len(res.GetStateHash()) == 0 {
		return nil
	}
	if res.GetRemoved() {
		// New logins stop now. Memory keeps the enrollment until the exit.
		cleared := c.state.Dropped()
		c.srv.SetAccess(cleared.Access())
		if err = cleared.Save(); err != nil {
			slog.Error("persist dropped enrollment on removal", "error", err)
		}
		return errDaemonRemoved
	}

	access := state.AccessFrom(res, c.state.TargetID)
	previousHostCA := c.state.Access().HostCA
	c.state.SetAccess(access)
	c.srv.SetAccess(access)
	c.srv.DropRevoked()

	// The watcher signs the new cert, so a failure never holds back a revoke.
	if access.HostCA != previousHostCA {
		select {
		case c.renew <- struct{}{}:
		default:
		}
	}
	return c.state.Save()
}

func (c *Client) renewHostCerts(ctx context.Context) error {
	renewed, err := hostcerts.RenewHostCerts(ctx, c.state.TargetID, c.state.Access().HostCA, c.signHostCert)
	if err != nil || !renewed {
		return err
	}
	c.srv.Reload()
	return nil
}

func (c *Client) signHostCert(ctx context.Context, pub []byte) (string, error) {
	res, err := c.ctl.SignHostCertificate(ctx, &nokkuv1.SignHostCertificateRequest{
		PublicKey: new(string(pub)),
	})
	if err != nil {
		return "", err
	}
	return res.GetSignedCertificate(), nil
}

// sshEndpoints is the address this host reaches the core from. A UDP connect sends nothing, it asks the kernel.
func (c *Client) sshEndpoints(ctx context.Context) []string {
	core, err := url.Parse(c.state.APIURL)
	if err != nil {
		return nil
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp4", net.JoinHostPort(core.Hostname(), cmp.Or(core.Port(), "443")))
	if err != nil {
		return nil
	}
	defer conn.Close()
	local, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil || local.Addr().IsLoopback() {
		return nil
	}
	return []string{netip.AddrPortFrom(local.Addr(), c.sshAddr.Port()).String()}
}
