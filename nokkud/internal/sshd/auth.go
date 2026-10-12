package sshd

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

var errNoCertificates = errors.New("sshd: only certificate authentication is supported")

func (s *Server) trustedCA(key ssh.PublicKey) bool {
	return s.trustedCAWire(string(key.Marshal()))
}

func (s *Server) trustedCAWire(wire string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.trustedCAs[wire]; ok {
		return true
	}
	until, ok := s.retiredCAs[wire]
	return ok && time.Now().Before(until)
}

// SetTrust with an empty active key trusts no CA. An emergency rollover sends no retired key.
func (s *Server) SetTrust(active string, retiredKeys []*nokkuv1.RetiredCAKey) {
	trusted := map[string]struct{}{}
	if active != "" {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(active))
		if err != nil {
			// Keep the last good set, a garbled key must not lock everyone out.
			slog.Warn("unreadable CA public key, keeping the previous trust", "error", err)
			return
		}
		trusted[string(pub.Marshal())] = struct{}{}
	}
	retired := make(map[string]time.Time, len(retiredKeys))
	for _, k := range retiredKeys {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.GetPublicKey()))
		if err != nil {
			slog.Warn("skipping unreadable retired CA", "error", err)
			continue
		}
		retired[string(pub.Marshal())] = k.GetTrustedUntil().AsTime()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trustedCAs = trusted
	s.retiredCAs = retired
}

// One certificate principal has to match the list synced for the requested account as a whole string.
func (s *Server) publicKeyCallback(
	conn ssh.ConnMetadata,
	key ssh.PublicKey,
) (*ssh.Permissions, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		// Clients offer every agent key before the certificate, so a plain key is noise, not an audit event.
		slog.Debug("ignoring plain public key", "user", conn.User(), "remote", conn.RemoteAddr())
		return nil, errNoCertificates
	}
	// CheckCert does not validate the cert type, so a host certificate from a shared CA could log in as a user.
	if cert.CertType != ssh.UserCert {
		return nil, s.deny(conn, fmt.Errorf("sshd: certificate has type %d, want user certificate", cert.CertType))
	}

	if !s.trustedCA(cert.SignatureKey) {
		return nil, s.deny(conn, errors.New("sshd: certificate signed by unrecognized authority"))
	}

	allowed := s.principals(conn.User())
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

	// Built per auth so a new trust applies at once. CheckCert enforces critical options, validity and signature.
	checker := ssh.CertChecker{
		IsUserAuthority:          s.trustedCA,
		SupportedCriticalOptions: []string{"force-command", "source-address"},
	}
	if err := checker.CheckCert(matched, cert); err != nil {
		return nil, s.deny(conn, err)
	}

	// The stack enforces CriticalOptions, the session Extensions. A nil Extensions map would panic on write.
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
	// The CA signature covers the key id, so the session can trust it to tell a web session from a direct login.
	perms.Extensions["nokku-cert-key-id"] = cert.KeyId
	if fc := cert.CriticalOptions["force-command"]; fc != "" {
		perms.Extensions["force-command"] = fc
	}
	return perms, nil
}

// accountKey is where the login's local account sits in the permissions.
const accountKey = "nokku-account"

// Runs once the client proved it holds the key. The account is checked here so nologin stops forwards too.
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
