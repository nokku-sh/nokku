package sshd

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/daemon/internal/state"
)

const accountKey = "nokku-account"

var errNoCertificates = errors.New("sshd: only certificate authentication is supported")

// access is one sync. It is swapped whole, so a login never sees half of one.
type access struct {
	principals map[string][]string
	policy     policy
	// The CA keys are in wire form. An empty active key trusts none.
	ca      string
	retired map[string]time.Time
}

func (a *access) trusts(wire string) bool {
	if a.ca != "" && wire == a.ca {
		return true
	}
	until, ok := a.retired[wire]
	return ok && time.Now().Before(until)
}

// SetAccess applies a sync to new logins, DropRevoked to open connections. An
// active CA key that does not parse trusts no CA, retired ones included. An
// emergency rollover sends no retired key.
func (s *Server) SetAccess(sa *state.Access) {
	a := &access{
		principals: sa.Principals,
		policy:     policyFrom(sa.DaemonConfig),
		retired:    make(map[string]time.Time, len(sa.RetiredCAs)),
	}
	if sa.CA != "" {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sa.CA))
		if err != nil {
			slog.Warn("unreadable CA public key, trusting no CA", "error", err)
			s.access.Store(a)
			return
		}
		a.ca = string(pub.Marshal())
	}
	for _, k := range sa.RetiredCAs {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.GetPublicKey()))
		if err != nil {
			slog.Warn("skipping unreadable retired CA", "error", err)
			continue
		}
		a.retired[string(pub.Marshal())] = k.GetTrustedUntil().AsTime()
	}
	s.access.Store(a)
}

// A cert principal must match the account's synced list as a whole string.
func (s *Server) publicKeyCallback(
	conn ssh.ConnMetadata,
	key ssh.PublicKey,
) (*ssh.Permissions, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		// Clients offer agent keys first, so a plain key is no audit event.
		slog.Debug("ignoring plain public key", "user", conn.User(), "remote", conn.RemoteAddr())
		return nil, errNoCertificates
	}
	// CheckCert skips the type, so a host cert from a shared CA could log in.
	if cert.CertType != ssh.UserCert {
		return nil, s.deny(conn, fmt.Errorf("sshd: certificate has type %d, want user certificate", cert.CertType))
	}

	// One sync answers every question of this login.
	a := s.access.Load()
	trusted := func(key ssh.PublicKey) bool { return a.trusts(string(key.Marshal())) }
	if !trusted(cert.SignatureKey) {
		return nil, s.deny(conn, errors.New("sshd: certificate signed by unrecognized authority"))
	}

	allowed := a.principals[conn.User()]
	if len(allowed) == 0 {
		return nil, s.deny(conn, fmt.Errorf("sshd: no access rules for user %q", conn.User()))
	}

	matched := ""
	for _, p := range allowed {
		if slices.Contains(cert.ValidPrincipals, p) {
			matched = p
			break
		}
	}
	if matched == "" {
		return nil, s.deny(
			conn,
			fmt.Errorf("sshd: certificate principal not authorized for user %q", conn.User()),
		)
	}

	// Built per auth so a new trust applies at once. CheckCert enforces
	// critical options, validity and signature.
	checker := ssh.CertChecker{
		IsUserAuthority:          trusted,
		SupportedCriticalOptions: []string{"force-command", "source-address"},
	}
	if err := checker.CheckCert(matched, cert); err != nil {
		return nil, s.deny(conn, err)
	}

	// The stack enforces CriticalOptions, the session Extensions.
	perms := &ssh.Permissions{
		CriticalOptions: maps.Clone(cert.CriticalOptions),
		Extensions:      maps.Clone(cert.Extensions),
	}
	if perms.Extensions == nil {
		perms.Extensions = make(map[string]string, 2)
	}
	perms.Extensions["nokku-principal"] = matched
	// DropRevoked closes the connection once this CA is no longer trusted.
	perms.Extensions["nokku-ca"] = string(cert.SignatureKey.Marshal())
	// The CA signs the key id, so a session can trust it to spot web logins.
	perms.Extensions["nokku-cert-key-id"] = cert.KeyId
	if fc := cert.CriticalOptions["force-command"]; fc != "" {
		perms.Extensions["force-command"] = fc
	}
	return perms, nil
}

// Runs after key proof. Checks the account here so nologin stops forwards too.
func (s *Server) verifiedPublicKey(
	conn ssh.ConnMetadata,
	_ ssh.PublicKey,
	perms *ssh.Permissions,
	_ string,
) (*ssh.Permissions, error) {
	sysUser, err := s.lookupAccount(conn.User())
	if err == nil {
		err = loginAllowed(sysUser, s.nologinFile)
	}
	if err != nil {
		return nil, s.deny(conn, err)
	}
	perms.ExtraData = map[any]any{accountKey: sysUser}

	ev := connEvent(conn, eventAuthSuccess)
	ev.Principal = perms.Extensions["nokku-principal"]
	s.emit(ev)
	return perms, nil
}

// Absent means deny.
func certExt(conn *ssh.ServerConn, name string) bool {
	if conn == nil || conn.Permissions == nil {
		return false
	}
	_, ok := conn.Permissions.Extensions[name]
	return ok
}

func (s *Server) deny(conn ssh.ConnMetadata, err error) error {
	ev := connEvent(conn, eventAuthFailure)
	ev.Error = err.Error()
	s.emit(ev)
	return err
}
