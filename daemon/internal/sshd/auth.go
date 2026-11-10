package sshd

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/daemon/internal/state"
)

const accountKey = "nokku-account"

// What a client of a stale daemon reads. Anyone who connects sees it, so it names no date and no person.
const staleNotice = "This server lost touch with Nokku and takes no new logins through it until it syncs again. " +
	"Its own sshd on port 22 is the way in.\r\n"

var (
	errNoCertificates = errors.New("sshd: only certificate authentication is supported")
	errStale          = errors.New("sshd: the access list is too old to trust")
)

// access is one sync. It is swapped whole, so a login never sees half of one.
type access struct {
	principals map[string][]string
	policy     policy
	// The CA key in wire form. Empty trusts none.
	ca string
	// When the core last confirmed all of this.
	syncedAt time.Time
}

// stale is true once the core has not confirmed the access for longer than any certificate lives. A CA that was
// rolled over since would still be trusted here, so new logins stop. Open sessions go on.
func (a *access) stale() bool {
	return time.Since(a.syncedAt) > login.MaxCertTTL
}

func (a *access) trusts(wire string) bool {
	return a.ca != "" && wire == a.ca
}

// SetAccess gates new logins, DropRevoked open ones. A CA key that does not parse trusts none.
func (s *Server) SetAccess(sa *state.Access) {
	a := &access{
		principals: sa.Principals,
		policy:     policyFrom(sa.DaemonConfig),
		syncedAt:   sa.SyncedAt,
	}
	if sa.CA != "" {
		if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sa.CA)); err != nil {
			slog.Warn("unreadable CA public key, trusting no CA", "error", err)
		} else {
			a.ca = string(pub.Marshal())
		}
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
	if a.stale() {
		return nil, s.deny(conn, errStale)
	}
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

// login runs after key proof. It checks the account here so nologin stops forwards too, then takes a connection
// slot, which leave gives back.
func (s *Server) login(conn ssh.ConnMetadata, perms *ssh.Permissions) (leave func(), err error) {
	sysUser, err := s.lookupAccount(conn.User())
	if err == nil {
		err = loginAllowed(sysUser, s.nologinFile)
	}
	if err == nil {
		leave, err = s.admit(perms.Extensions["nokku-principal"])
	}
	if err != nil {
		return nil, s.deny(conn, err)
	}
	perms.ExtraData = map[any]any{accountKey: sysUser}

	ev := connEvent(conn, eventAuthSuccess)
	ev.Principal = perms.Extensions["nokku-principal"]
	s.emit(ev)
	return leave, nil
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
