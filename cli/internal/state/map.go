package state

import (
	"log/slog"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/cli/internal/ui"
)

// FromAccess strips control characters from names, see Targets for ids.
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

	c.CA = MapCA(res.GetCertificateAuthority())
	for _, access := range res.GetTargets() {
		if !validID(access.GetTarget().GetId()) {
			continue
		}
		target := MapTarget(access.GetTarget())
		for _, l := range access.GetLogins() {
			username := ui.PlainLine(l.GetUsername())
			target.Usernames = append(target.Usernames, username)
			if l.GetExpiresAt() == nil {
				continue
			}
			if target.Until == nil {
				target.Until = make(map[string]time.Time)
			}
			target.Until[username] = l.GetExpiresAt().AsTime()
		}
		c.Targets = append(c.Targets, target)
	}
	return c
}

// Targets drops ids that are no UUID, they end up in file paths and ssh files.
func Targets(targets []*nokkuv1.Target) []Target {
	var out []Target
	for _, t := range targets {
		if validID(t.GetId()) {
			out = append(out, MapTarget(t))
		}
	}
	return out
}

// MapCA is nil without a CA, a subject with no targets gets none.
func MapCA(ca *nokkuv1.CertificateAuthority) *CA {
	if ca == nil {
		return nil
	}
	return &CA{
		UserPublicKey: ca.GetUserPublicKey(),
		HostPublicKey: ca.GetHostPublicKey(),
		RotatedAt:     timeOf(ca.GetRotatedAt()),
	}
}

func MapTarget(t *nokkuv1.Target) Target {
	return Target{
		ID:            t.GetId(),
		Daemon:        t.GetDaemon() != nil,
		Name:          ui.PlainLine(t.GetName()),
		Endpoints:     plainAll(t.GetEndpoints()),
		HostPublicKey: t.GetHostPublicKey(),
		ManualSyncAt:  timeOf(t.GetManualSyncAt()),
		CreatedBy:     t.GetCreatedBy(),
	}
}

// timeOf keeps an unset timestamp zero, AsTime would make it 1970.
func timeOf(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

func plainAll(values []string) []string {
	for i, v := range values {
		values[i] = ui.PlainLine(v)
	}
	return values
}

func validID(id string) bool {
	if login.ValidID(id) {
		return true
	}
	slog.Warn("ignoring core entry with an invalid id", "id", id)
	return false
}
