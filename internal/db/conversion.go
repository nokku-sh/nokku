package db

import (
	"encoding/json"
	"log/slog"
	"time"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func mapSlice[T, R any](in []T, fn func(T) R) []R {
	if in == nil {
		return nil
	}
	out := make([]R, len(in))
	for i, v := range in {
		out[i] = fn(v)
	}
	return out
}

// jsonMap logs a malformed blob and returns an empty map, the row is still
// readable without it.
func jsonMap(column string, raw []byte) map[string]string {
	m := make(map[string]string)
	if len(raw) == 0 {
		return m
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		slog.Warn("dropping malformed jsonb column", "column", column, "error", err)
	}
	return m
}

func (w *Workspace) ToProto() *nokkuv1.Workspace {
	if w == nil {
		return nil
	}
	// A copy, so the stored row keeps what the admin actually set.
	settings := &nokkuv1.WorkspaceSettings{}
	if w.Settings != nil {
		settings = proto.CloneOf(w.Settings)
	}
	settings.DefaultDaemonConfig = ResolveDaemonConfig(settings.GetDefaultDaemonConfig())
	return &nokkuv1.Workspace{
		Id:          &w.ID,
		Slug:        &w.Slug,
		Name:        &w.Name,
		Description: w.Description,
		Settings:    settings,
		CreatedAt:   SafeTimestamp(&w.CreatedAt),
		UpdatedAt:   SafeTimestamp(&w.UpdatedAt),
	}
}

func (c *Credential) ToProto() *nokkuv1.AccountCredential {
	if c == nil {
		return nil
	}
	return &nokkuv1.AccountCredential{
		Id:         &c.ID,
		Type:       &c.Type,
		Provider:   &c.Provider,
		Subject:    &c.Subject,
		Label:      &c.Label,
		CreatedAt:  SafeTimestamp(&c.CreatedAt),
		LastUsedAt: SafeTimestamp(c.LastUsedAt),
	}
}

func (r *Recording) ToProto() *nokkuv1.Recording {
	if r == nil {
		return nil
	}
	return &nokkuv1.Recording{
		Id:         &r.ID,
		DaemonId:   r.DaemonID,
		DaemonName: &r.DaemonName,
		Username:   &r.Username,
		SubjectId:  r.SubjectID,
		Principal:  &r.Principal,
		StartedAt:  SafeTimestamp(&r.StartedAt),
		EndedAt:    SafeTimestamp(r.EndedAt),
		SizeBytes:  &r.SizeBytes,
		Complete:   &r.Complete,
	}
}

func (t *Team) ToProto() *nokkuv1.Team {
	if t == nil {
		return nil
	}
	return &nokkuv1.Team{
		Id:          &t.ID,
		Name:        &t.Name,
		Description: t.Description,
		Tags:        t.Tags,
		CreatedAt:   SafeTimestamp(&t.CreatedAt),
		UpdatedAt:   SafeTimestamp(&t.UpdatedAt),
	}
}

func TeamsToProto(rows []*ListTeamsRow) []*nokkuv1.Team {
	return mapSlice(rows, func(r *ListTeamsRow) *nokkuv1.Team { return r.Team.ToProto() })
}

func (s *ServiceAccount) ToProto() *nokkuv1.ServiceAccount {
	if s == nil {
		return nil
	}
	return &nokkuv1.ServiceAccount{
		Id:          &s.ID,
		Name:        &s.Name,
		Description: s.Description,
		Role:        &s.Role,
		Tags:        s.Tags,
		LastUsedAt:  SafeTimestamp(s.LastUsedAt),
		CreatedAt:   SafeTimestamp(&s.CreatedAt),
		UpdatedAt:   SafeTimestamp(&s.UpdatedAt),
	}
}

func ServiceAccountsToProto(rows []*ListServiceAccountsRow) []*nokkuv1.ServiceAccount {
	return mapSlice(rows, func(r *ListServiceAccountsRow) *nokkuv1.ServiceAccount {
		return r.ServiceAccount.ToProto()
	})
}

func (t *AccessToken) ToServiceAccountToken() *nokkuv1.ServiceAccountToken {
	return &nokkuv1.ServiceAccountToken{
		Id:         &t.ID,
		Label:      &t.Label,
		ExpiresAt:  SafeTimestamp(t.ExpiresAt),
		LastUsedAt: SafeTimestamp(t.LastSeenAt),
		CreatedAt:  SafeTimestamp(&t.CreatedAt),
	}
}

func ServiceAccountTokensToProto(ts []*AccessToken) []*nokkuv1.ServiceAccountToken {
	return mapSlice(ts, func(t *AccessToken) *nokkuv1.ServiceAccountToken { return t.ToServiceAccountToken() })
}

func (t *Target) ToProto() *nokkuv1.Target {
	if t == nil {
		return nil
	}

	metadata := jsonMap("targets.metadata", t.Metadata)
	return &nokkuv1.Target{
		Id:            &t.ID,
		DaemonId:      t.DaemonID,
		CaId:          t.CaID,
		Description:   t.Description,
		Name:          &t.Name,
		Endpoints:     t.Endpoints,
		Tags:          t.Tags,
		Metadata:      metadata,
		HostPublicKey: t.HostPublicKey,
		CreatedAt:     SafeTimestamp(&t.CreatedAt),
		UpdatedAt:     SafeTimestamp(&t.UpdatedAt),
	}
}

func (a *TargetAccount) ToProto() *nokkuv1.TargetAccount {
	if a == nil {
		return nil
	}
	return &nokkuv1.TargetAccount{
		Id:        &a.ID,
		TargetId:  &a.TargetID,
		Username:  &a.Username,
		CreatedAt: SafeTimestamp(&a.CreatedAt),
	}
}

func (p *GetTargetAccountsByTargetIDsRow) ToProto() *nokkuv1.TargetAccount {
	if p == nil {
		return nil
	}

	out := p.TargetAccount.ToProto()
	out.UserIds = p.UserIds
	out.TeamIds = p.TeamIds
	out.ServiceAccountIds = p.ServiceAccountIds
	return out
}

func (u *User) ToProto() *nokkuv1.User {
	if u == nil {
		return nil
	}
	return &nokkuv1.User{
		Id:        &u.ID,
		Name:      &u.Name,
		Email:     &u.Email,
		Picture:   u.Picture,
		Role:      &u.Role,
		Active:    &u.Active,
		CreatedAt: SafeTimestamp(&u.CreatedAt),
		UpdatedAt: SafeTimestamp(&u.UpdatedAt),
	}
}

func UsersToProto(rows []*ListUsersRow) []*nokkuv1.User {
	return mapSlice(rows, func(r *ListUsersRow) *nokkuv1.User { return r.User.ToProto() })
}

const DaemonOnlineWindow = 30 * time.Second

// MaxTargetAccounts stops a host from reporting accounts without bound.
const MaxTargetAccounts = 1000

func SeenRecently(t *time.Time) bool {
	return t != nil && time.Since(*t) < DaemonOnlineWindow
}

// DefaultDaemonConfig is what a daemon enforces when nothing says otherwise.
// nokkud's DefaultPolicy holds the same values for the time before its first
// sync.
func DefaultDaemonConfig() *nokkuv1.DaemonConfig {
	return &nokkuv1.DaemonConfig{
		RecordSessions:       new(true),
		AllowForwarding:      new(true),
		AllowAgentForwarding: new(true),
		GatewayPorts:         new(false),
	}
}

// ResolveDaemonConfig fills the fields cfg leaves unset with the defaults, so
// the daemon, the API and the UI never read an unset field differently.
func ResolveDaemonConfig(cfg *nokkuv1.DaemonConfig) *nokkuv1.DaemonConfig {
	resolved := DefaultDaemonConfig()
	if cfg != nil {
		proto.Merge(resolved, cfg)
	}
	return resolved
}

func (d *Daemon) ToProto() *nokkuv1.Daemon {
	if d == nil {
		return nil
	}
	metadata := jsonMap("daemons.metadata", d.Metadata)
	return &nokkuv1.Daemon{
		Id:         &d.ID,
		Name:       &d.Name,
		Status:     &d.Status,
		Config:     ResolveDaemonConfig(d.Config),
		Online:     new(SeenRecently(d.LastSeenAt)),
		LastSeenAt: SafeTimestamp(d.LastSeenAt),
		Metadata:   metadata,
		UpdatedAt:  SafeTimestamp(&d.UpdatedAt),
		CreatedAt:  SafeTimestamp(&d.CreatedAt),
	}
}

func DaemonsToProto(rows []*ListDaemonsRow) []*nokkuv1.Daemon {
	return mapSlice(rows, func(r *ListDaemonsRow) *nokkuv1.Daemon { return r.Daemon.ToProto() })
}

func (r *SSHCA) ToProto() *nokkuv1.CertificateAuthority {
	if r == nil {
		return nil
	}

	extensions, err := ParseExtensionsMap(r.UserExtensions)
	if err != nil {
		slog.Warn("failed to parse extensions", "error", err)
		extensions = nil
	}
	criticalOptions, err := ParseCriticalOptionsMap(r.UserCriticalOptions)
	if err != nil {
		slog.Warn("failed to parse critical options", "error", err)
		criticalOptions = nil
	}

	return &nokkuv1.CertificateAuthority{
		Id:                   &r.ID,
		Name:                 &r.Name,
		Description:          r.Description,
		PublicKey:            &r.PublicKey,
		NotBefore:            SafeTimestamp(&r.NotBefore),
		NotAfter:             SafeTimestamp(&r.NotAfter),
		IsActive:             &r.IsActive,
		IsDefault:            &r.IsDefault,
		KeyType:              &r.KeyType,
		KeyBits:              &r.KeyBits,
		CreatedAt:            SafeTimestamp(&r.CreatedAt),
		UpdatedAt:            SafeTimestamp(&r.UpdatedAt),
		UserDefaultTtl:       durationpb.New(r.UserDefaultTtl),
		UserMaxTtl:           durationpb.New(r.UserMaxTtl),
		UserExtensions:       extensions,
		UserCriticalOptions:  criticalOptions,
		AllowedKeyTypes:      r.AllowedKeyTypes,
		Lifetime:             durationpb.New(r.Lifetime),
		HostDefaultTtl:       durationpb.New(r.HostDefaultTtl),
		HostMaxTtl:           durationpb.New(r.HostMaxTtl),
		PreviousPublicKey:    r.PreviousPublicKey,
		PreviousTrustedUntil: SafeTimestamp(r.PreviousTrustedUntil),
	}
}

func CAsToProto(cas []*SSHCA) []*nokkuv1.CertificateAuthority {
	return mapSlice(cas, func(ca *SSHCA) *nokkuv1.CertificateAuthority { return ca.ToProto() })
}

// ToProto leaves out the private fields.
func (r *GetCAsByIDsRow) ToProto() *nokkuv1.CertificateAuthority {
	if r == nil {
		return nil
	}
	return &nokkuv1.CertificateAuthority{
		Id:             &r.ID,
		Name:           &r.Name,
		PublicKey:      &r.PublicKey,
		IsDefault:      &r.IsDefault,
		UserDefaultTtl: durationpb.New(r.UserDefaultTtl),
		UserMaxTtl:     durationpb.New(r.UserMaxTtl),
	}
}

func (p *ListTargetAccountsRow) ToProto() *nokkuv1.TargetAccount {
	if p == nil {
		return nil
	}

	out := p.TargetAccount.ToProto()
	out.UserIds = p.UserIds
	out.TeamIds = p.TeamIds
	out.ServiceAccountIds = p.ServiceAccountIds
	return out
}

func TargetAccountsToProto(rows []*ListTargetAccountsRow) []*nokkuv1.TargetAccount {
	return mapSlice(rows, func(r *ListTargetAccountsRow) *nokkuv1.TargetAccount { return r.ToProto() })
}

func (t *JoinToken) ToProto() *nokkuv1.JoinToken {
	return &nokkuv1.JoinToken{
		Id:          &t.ID,
		Kind:        &t.Kind,
		Label:       &t.Label,
		ExpiresAt:   SafeTimestamp(t.ExpiresAt),
		MaxUses:     t.MaxUses,
		Uses:        &t.Uses,
		AutoApprove: &t.AutoApprove,
		CaId:        t.CaID,
		Role:        t.Role,
		CreatedAt:   SafeTimestamp(&t.CreatedAt),
		LastUsedAt:  SafeTimestamp(t.LastUsedAt),
	}
}

func JoinTokensToProto(ts []*JoinToken) []*nokkuv1.JoinToken {
	return mapSlice(ts, func(t *JoinToken) *nokkuv1.JoinToken { return t.ToProto() })
}
