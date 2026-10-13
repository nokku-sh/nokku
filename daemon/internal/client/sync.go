package client

import (
	"context"
	"log/slog"
	"net"
	"strconv"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/daemon/internal/hostcerts"
	"github.com/nokku-sh/nokku/daemon/internal/sshd"
	"github.com/nokku-sh/nokku/daemon/internal/state"
	"github.com/nokku-sh/nokku/daemon/internal/sysutil"
)

// A failed sync leaves the cache as it was, so auth keeps working.
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
		// Drop the enrollment on disk only. The in-memory config is read concurrently and the process exits.
		c.cache.Clear()
		if err = c.cache.Save(); err != nil {
			slog.Error("persist cleared cache on rejection", "error", err)
		}
		if err = (&state.Config{APIURL: c.config.APIURL, APICA: c.config.APICA}).Save(); err != nil {
			slog.Error("persist cleared config on rejection", "error", err)
		}
		return errDaemonRejected
	case nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED:
	case nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING:
		// A pending answer carries no principals and no CA, so applying it takes an earlier approval back.
	case nokkuv1.DaemonStatus_DAEMON_STATUS_UNSPECIFIED:
		return nil
	}

	principals := make(map[string][]string, len(res.GetPrincipals()))
	for _, p := range res.GetPrincipals() {
		principals[p.GetUsername()] = p.GetCertPrincipals()
	}
	previousCA, _ := c.cache.CAs()
	c.cache.Replace(principals, res.GetConfig(), res.GetCaPublicKey(), res.GetRetiredCaKeys(), res.GetStateVersion())
	c.srv.SetPolicy(sshd.PolicyFrom(res.GetConfig()))
	c.srv.SetTrust(res.GetCaPublicKey(), res.GetRetiredCaKeys())
	c.srv.DropRevoked()

	// A new CA needs a new host certificate. The watcher signs it so a failure never holds back a revoke.
	if res.GetCaPublicKey() != previousCA {
		select {
		case c.renew <- struct{}{}:
		default:
		}
	}
	return c.cache.Save()
}

func (c *Client) renewHostCerts(ctx context.Context) error {
	ca, _ := c.cache.CAs()
	renewed, err := hostcerts.RenewHostCerts(ctx, c.config.TargetID, ca, c.signHostCert)
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
