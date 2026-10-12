package state

import (
	"log/slog"
	"strings"
	"unicode"
	"uuid"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

// FromAccess maps the backend access snapshot. IDs end up in file paths and
// generated ssh files, so anything that is not a UUID is dropped here, once.
// Names end up on the terminal, so they lose their control characters here.
func FromAccess(res *nokkuv1.GetMyAccessResponse) Cache {
	var c Cache
	switch subject := res.GetSubject().(type) {
	case *nokkuv1.GetMyAccessResponse_User:
		u := subject.User
		c.User = &User{ID: u.GetId(), Name: plain(u.GetName()), Email: plain(u.GetEmail())}
	case *nokkuv1.GetMyAccessResponse_ServiceAccount:
		sa := subject.ServiceAccount
		c.ServiceAccount = &ServiceAccount{ID: sa.GetId(), Name: plain(sa.GetName())}
	}

	c.CAs = SSHCAs(res.GetCertificateAuthorities())
	for _, t := range res.GetTargets() {
		if !validIDs(t.GetId(), t.GetCaId()) || t.GetDaemonId() != "" && !validIDs(t.GetDaemonId()) {
			continue
		}
		c.Targets = append(c.Targets, MapTarget(t))
	}
	return c
}

// SSHCAs maps the CAs of a backend answer.
func SSHCAs(cas []*nokkuv1.CertificateAuthority) []CA {
	var out []CA
	for _, ca := range cas {
		if !validIDs(ca.GetId()) {
			continue
		}
		entry := CA{
			ID:        ca.GetId(),
			Name:      plain(ca.GetName()),
			PublicKey: ca.GetPublicKey(),
			Default:   ca.GetIsDefault(),
		}
		// AsTime turns an unset timestamp into 1970, not the zero time.
		if ca.GetNotBefore() != nil {
			entry.RotatedAt = ca.GetNotBefore().AsTime()
		}
		if ca.GetPreviousTrustedUntil() != nil {
			entry.PreviousPublicKey = ca.GetPreviousPublicKey()
			entry.PreviousTrustedUntil = ca.GetPreviousTrustedUntil().AsTime()
		}
		out = append(out, entry)
	}
	return out
}

func MapTarget(t *nokkuv1.Target) Target {
	return Target{
		ID:            t.GetId(),
		CAID:          t.GetCaId(),
		DaemonID:      t.GetDaemonId(),
		Name:          plain(t.GetName()),
		Endpoints:     plainAll(t.GetEndpoints()),
		Usernames:     plainAll(t.GetUsernames()),
		HostPublicKey: t.GetHostPublicKey(),
		Metadata:      t.GetMetadata(),
	}
}

// plain drops control characters, which would start an escape sequence once
// the value is printed.
func plain(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

func plainAll(values []string) []string {
	for i, v := range values {
		values[i] = plain(v)
	}
	return values
}

func validIDs(ids ...string) bool {
	for _, id := range ids {
		// Only the canonical form, which is safe as a path segment and ssh token.
		if u, err := uuid.Parse(id); err != nil || u.String() != id {
			slog.Warn("ignoring backend entry with an invalid id", "id", id)
			return false
		}
	}
	return true
}
