package state

import (
	"log/slog"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/cli/internal/ui"
)

// FromAccess drops ids that are no UUID, they end up in file paths and ssh files. Names lose their control characters.
func FromAccess(res *nokkuv1.GetSubjectAccessResponse) Cache {
	var c Cache
	switch subject := res.GetSubject().(type) {
	case *nokkuv1.GetSubjectAccessResponse_User:
		u := subject.User
		c.User = &User{ID: u.GetId(), Name: ui.PlainLine(u.GetName()), Email: ui.PlainLine(u.GetEmail())}
	case *nokkuv1.GetSubjectAccessResponse_ServiceAccount:
		sa := subject.ServiceAccount
		c.ServiceAccount = &ServiceAccount{ID: sa.GetId(), Name: ui.PlainLine(sa.GetName())}
	}

	c.CAs = SSHCAs(res.GetCertificateAuthorities())
	c.Targets = Targets(res.GetTargets())
	return c
}

// Targets drops ids that are no UUID, they end up in file paths and ssh files.
func Targets(targets []*nokkuv1.Target) []Target {
	var out []Target
	for _, t := range targets {
		if !validIDs(t.GetId(), t.GetCaId()) || t.GetDaemonId() != "" && !validIDs(t.GetDaemonId()) {
			continue
		}
		out = append(out, MapTarget(t))
	}
	return out
}

func SSHCAs(cas []*nokkuv1.CertificateAuthority) []CA {
	var out []CA
	for _, ca := range cas {
		if !validIDs(ca.GetId()) {
			continue
		}
		entry := CA{
			ID:            ca.GetId(),
			Name:          ui.PlainLine(ca.GetName()),
			PublicKey:     ca.GetPublicKey(),
			HostPublicKey: ca.GetHostPublicKey(),
			Default:       ca.GetIsDefault(),
		}
		// AsTime turns an unset timestamp into 1970, not the zero time.
		if ca.GetPreviousTrustedUntil() != nil {
			entry.PreviousPublicKey = ca.GetPreviousPublicKey()
			entry.PreviousHostPublicKey = ca.GetPreviousHostPublicKey()
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
		Name:          ui.PlainLine(t.GetName()),
		Endpoints:     plainAll(t.GetEndpoints()),
		Usernames:     plainAll(t.GetUsernames()),
		Until:         untilAll(t.GetUsernameExpiresAt()),
		HostPublicKey: t.GetHostPublicKey(),
	}
}

func untilAll(ends map[string]*timestamppb.Timestamp) map[string]time.Time {
	if len(ends) == 0 {
		return nil
	}
	out := make(map[string]time.Time, len(ends))
	for username, end := range ends {
		out[ui.PlainLine(username)] = end.AsTime()
	}
	return out
}

func plainAll(values []string) []string {
	for i, v := range values {
		values[i] = ui.PlainLine(v)
	}
	return values
}

func validIDs(ids ...string) bool {
	for _, id := range ids {
		if !login.ValidID(id) {
			slog.Warn("ignoring core entry with an invalid id", "id", id)
			return false
		}
	}
	return true
}
