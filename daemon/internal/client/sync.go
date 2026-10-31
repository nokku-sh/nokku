package client

import (
	"context"
	"log/slog"
	"net"
	"strconv"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/daemon/internal/hostcerts"
	"github.com/nokku-sh/nokku/daemon/internal/state"
	"github.com/nokku-sh/nokku/daemon/internal/sysutil"
)

// A failed sync leaves the access as it was, so auth keeps working. A failed save keeps the new access in memory.
func (c *Client) syncDaemon(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	res, err := c.ctl.SyncDaemon(ctx, &nokkuv1.SyncDaemonRequest{
		PrivateIps: c.sshEndpoints(),
		Users:      sysutil.SystemUsers(),
		Metadata:   sysutil.Metadata(),
	})
	if err != nil {
		return err
	}

	switch res.GetStatus() {
	case nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED:
		// New logins stop at once. The enrollment goes on disk only, the one in memory is read until the exit.
		cleared := c.state.Dropped()
		c.srv.SetAccess(cleared.Access())
		if err = cleared.Save(); err != nil {
			slog.Error("persist dropped enrollment on rejection", "error", err)
		}
		return errDaemonRejected
	case nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED:
	case nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING:
		// A pending answer carries no principals and no CA, so applying it takes an earlier approval back.
	case nokkuv1.DaemonStatus_DAEMON_STATUS_UNSPECIFIED:
		return nil
	}

	access := state.AccessFrom(res)
	previousHostCA := c.state.Access().HostCA
	c.state.SetAccess(access)
	c.srv.SetAccess(access)
	c.srv.DropRevoked()

	// A new host CA needs a new host certificate. The watcher signs it so a failure never holds back a revoke.
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

func (c *Client) sshEndpoints() []string {
	port := strconv.Itoa(int(c.sshAddr.Port()))
	var endpoints []string
	for _, ip := range sysutil.PrivateIPs() {
		endpoints = append(endpoints, net.JoinHostPort(ip, port))
	}
	return endpoints
}
