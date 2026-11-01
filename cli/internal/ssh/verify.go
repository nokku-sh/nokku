package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/mizuchilabs/kata/fsutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

// Long enough for a key exchange on a local network.
const verifyTimeout = 2 * time.Second

var (
	cgnat = netip.MustParsePrefix("100.64.0.0/10")

	// A daemon shows a host cert, known_hosts trusts nothing else for it.
	hostCertAlgos = []string{
		ssh.CertAlgoED25519v01, ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01,
		ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01,
	}

	errHostKeyChecked = errors.New("host key checked")
)

// A private address of a target with another way in: relay or second endpoint.
func needsVerify(target *state.Target, addr string) bool {
	return (!target.Manual() || len(target.Endpoints) > 1) && privateAddr(addr)
}

// An address another network can reuse, like the user's own NAS at home.
func privateAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip)
}

// Runs a key exchange on its own connection, against ssh's known_hosts.
func verifyHost(ctx context.Context, addr string, target *state.Target) error {
	check, err := knownhosts.New(paths.KnownHostsFile())
	if err != nil {
		return fmt.Errorf("reading known hosts: %w", err)
	}
	d := net.Dialer{Timeout: verifyTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(verifyTimeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	checked := false
	var keyErr error
	_, _, _, err = ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		HostKeyCallback: func(_ string, remote net.Addr, key ssh.PublicKey) error {
			// The target id is the HostKeyAlias in ssh_config.
			checked, keyErr = true, check(net.JoinHostPort(target.ID, "22"), remote, key)
			return errHostKeyChecked
		},
		HostKeyAlgorithms: hostKeyAlgos(target),
	})
	if !checked {
		return fmt.Errorf("checking the host at %s: %w", addr, err)
	}
	if keyErr != nil {
		return fmt.Errorf("%s is not %s, its host key does not match: %w", addr, target.Name, keyErr)
	}
	return nil
}

// Asks for the key kind known_hosts has, or a host may offer another one.
func hostKeyAlgos(target *state.Target) []string {
	if !target.Manual() {
		return hostCertAlgos
	}
	pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(target.HostPublicKey))
	if err != nil {
		return nil
	}
	if pinned.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{pinned.Type()}
}

// PinnedHostOptions writes knownHosts and has ssh accept only the synced key.
func PinnedHostOptions(target *state.Target, knownHosts string) ([]string, error) {
	key := strings.TrimSpace(target.HostPublicKey)
	if !safeLine(key) {
		return nil, fmt.Errorf("the pinned host key of %s is unusable, run again with --accept-host-key", target.Name)
	}
	if err := fsutil.WriteFile(knownHosts, []byte(target.ID+" "+key+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("writing the pinned host key: %w", err)
	}
	opts := append(knownHostsOptions(target.ID, knownHosts), "-o", "StrictHostKeyChecking=yes")
	if algos := hostKeyAlgos(target); len(algos) > 0 {
		opts = append(opts, "-o", "HostKeyAlgorithms="+strings.Join(algos, ","))
	}
	return opts, nil
}

// AcceptHostOptions trusts any key, known_hosts may still hold the old one.
func AcceptHostOptions(target *state.Target, knownHosts string) []string {
	return append(knownHostsOptions(target.ID, knownHosts), "-o", "StrictHostKeyChecking=accept-new")
}

// Leaves ssh no trust but the file: no DNS, no command from the user's config.
func knownHostsOptions(alias, knownHosts string) []string {
	file := configValue(knownHosts)
	return []string{
		"-o", "HostKeyAlias=" + alias,
		"-o", "UserKnownHostsFile=" + file,
		"-o", "GlobalKnownHostsFile=" + file,
		"-o", "VerifyHostKeyDNS=no",
		// ssh before 8.5 has no KnownHostsCommand and would refuse to start.
		"-o", "IgnoreUnknown=KnownHostsCommand",
		"-o", "KnownHostsCommand=none",
	}
}
