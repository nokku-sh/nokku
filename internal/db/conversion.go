package db

import (
	"encoding/json"
	"log/slog"
	"time"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/util"
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
	return &nokkuv1.Workspace{
		Id:          &w.ID,
		Name:        &w.Name,
		Description: w.Description,
		Settings:    w.Settings,
		CreatedBy:   &w.CreatedBy,
		CreatedAt:   SafeTimestamp(&w.CreatedAt),
		UpdatedAt:   SafeTimestamp(&w.UpdatedAt),
	}
}

func WorkspacesToProto(ws []*Workspace) []*nokkuv1.Workspace {
	return mapSlice(
		ws,
		func(w *Workspace) *nokkuv1.Workspace { return w.ToProto() },
	)
}

func (w *CreateWorkspaceRow) ToProto() *nokkuv1.Workspace {
	if w == nil {
		return nil
	}
	return &nokkuv1.Workspace{
		Id:          &w.ID,
		Name:        &w.Name,
		Description: w.Description,
		CreatedBy:   &w.CreatedBy,
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
		Id:          &r.ID,
		WorkspaceId: &r.WorkspaceID,
		DaemonId:    &r.DaemonID,
		Username:    &r.Username,
		StartedAt:   SafeTimestamp(&r.StartedAt),
		EndedAt:     SafeTimestamp(r.EndedAt),
		SizeBytes:   &r.SizeBytes,
		Complete:    &r.Complete,
	}
}

func (t *Team) ToProto() *nokkuv1.Team {
	if t == nil {
		return nil
	}
	return &nokkuv1.Team{
		Id:          &t.ID,
		WorkspaceId: &t.WorkspaceID,
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
		WorkspaceId: &s.WorkspaceID,
		Name:        &s.Name,
		Description: s.Description,
		RoleName:    &s.RoleName,
		Tags:        s.Tags,
		ExpiresAt:   SafeTimestamp(s.ExpiresAt),
		CreatedAt:   SafeTimestamp(&s.CreatedAt),
		UpdatedAt:   SafeTimestamp(&s.UpdatedAt),
	}
}

func ServiceAccountsToProto(rows []*ListServiceAccountsRow) []*nokkuv1.ServiceAccount {
	return mapSlice(
		rows,
		func(r *ListServiceAccountsRow) *nokkuv1.ServiceAccount { return r.ServiceAccount.ToProto() },
	)
}

func (t *Target) ToProto() *nokkuv1.Target {
	if t == nil {
		return nil
	}

	metadata := jsonMap("targets.metadata", t.Metadata)
	return &nokkuv1.Target{
		Id:            &t.ID,
		WorkspaceId:   &t.WorkspaceID,
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

func TargetsToProto(rows []*ListTargetsRow) []*nokkuv1.Target {
	return mapSlice(rows, func(r *ListTargetsRow) *nokkuv1.Target { return r.Target.ToProto() })
}

func (p *Principal) ToProto() *nokkuv1.Principal {
	if p == nil {
		return nil
	}
	return &nokkuv1.Principal{
		Id:        &p.ID,
		TargetId:  &p.TargetID,
		Username:  &p.Username,
		CreatedAt: SafeTimestamp(&p.CreatedAt),
	}
}

func (p *GetPrincipalsByTargetIDsRow) ToProto() *nokkuv1.Principal {
	if p == nil {
		return nil
	}

	out := p.Principal.ToProto()
	out.UserIds = p.UserIds
	out.TeamIds = p.TeamIds
	out.ServiceAccountIds = p.ServiceAccountIds
	return out
}

func (u *User) ToProto() *nokkuv1.User {
	return &nokkuv1.User{
		Id:                   &u.ID,
		Name:                 &u.Name,
		Email:                &u.Email,
		EmailVerified:        &u.EmailVerified,
		Picture:              u.Picture,
		CreatedAt:            SafeTimestamp(&u.CreatedAt),
		UpdatedAt:            SafeTimestamp(&u.UpdatedAt),
		DisablePasswordReset: &u.DisablePasswordReset,
	}
}

const DaemonOnlineWindow = 30 * time.Second

func SeenRecently(t *time.Time) bool {
	return t != nil && time.Since(*t) < DaemonOnlineWindow
}

func (d *Daemon) ToProto() *nokkuv1.Daemon {
	if d == nil {
		return nil
	}
	metadata := jsonMap("daemons.metadata", d.Metadata)
	return &nokkuv1.Daemon{
		Id:          &d.ID,
		WorkspaceId: &d.WorkspaceID,
		Name:        &d.Name,
		Status:      &d.Status,
		Config:      d.Config,
		Online:      new(SeenRecently(d.LastSeenAt)),
		LastSeenAt:  SafeTimestamp(d.LastSeenAt),
		Metadata:    metadata,
		UpdatedAt:   SafeTimestamp(&d.UpdatedAt),
		CreatedAt:   SafeTimestamp(&d.CreatedAt),
	}
}

func DaemonsToProto(rows []*ListDaemonsRow) []*nokkuv1.Daemon {
	return mapSlice(rows, func(r *ListDaemonsRow) *nokkuv1.Daemon { return r.Daemon.ToProto() })
}

func (r *CertificateAuthority) ToProto() *nokkuv1.CertificateAuthority {
	if r == nil {
		return nil
	}

	extensions, err := util.ParseExtensionsMap(r.UserExtensions)
	if err != nil {
		slog.Warn("failed to parse extensions", "error", err)
		extensions = nil
	}
	criticalOptions, err := util.ParseCriticalOptionsMap(r.UserCriticalOptions)
	if err != nil {
		slog.Warn("failed to parse critical options", "error", err)
		criticalOptions = nil
	}

	return &nokkuv1.CertificateAuthority{
		Id:                  &r.ID,
		WorkspaceId:         &r.WorkspaceID,
		Name:                &r.Name,
		Description:         r.Description,
		Certificate:         &r.Certificate,
		PublicKey:           &r.PublicKey,
		SerialNumber:        &r.SerialNumber,
		Subject:             &r.Subject,
		NotBefore:           SafeTimestamp(&r.NotBefore),
		NotAfter:            SafeTimestamp(&r.NotAfter),
		IsActive:            &r.IsActive,
		IsDefault:           &r.IsDefault,
		KeyType:             &r.KeyType,
		AuthorityType:       &r.AuthorityType,
		KeyBits:             &r.KeyBits,
		CreatedAt:           SafeTimestamp(&r.CreatedAt),
		UpdatedAt:           SafeTimestamp(&r.UpdatedAt),
		UserDefaultTtl:      SafeDuration(&r.UserDefaultTtl),
		UserMaxTtl:          SafeDuration(&r.UserMaxTtl),
		UserExtensions:      extensions,
		UserCriticalOptions: criticalOptions,
		AllowedKeyTypes:     r.AllowedKeyTypes,
		Lifetime:            SafeDuration(&r.Lifetime),
		HostDefaultTtl:      SafeDuration(&r.HostDefaultTtl),
		HostMaxTtl:          SafeDuration(&r.HostMaxTtl),
	}
}

func CAsToProto(cas []*CertificateAuthority) []*nokkuv1.CertificateAuthority {
	return mapSlice(
		cas,
		func(rca *CertificateAuthority) *nokkuv1.CertificateAuthority { return rca.ToProto() },
	)
}

// ToProto leaves out the private fields.
func (r *GetCAsByIDsRow) ToProto() *nokkuv1.CertificateAuthority {
	if r == nil {
		return nil
	}
	return &nokkuv1.CertificateAuthority{
		Id:             &r.ID,
		WorkspaceId:    &r.WorkspaceID,
		Name:           &r.Name,
		PublicKey:      &r.PublicKey,
		IsDefault:      &r.IsDefault,
		AuthorityType:  &r.AuthorityType,
		Certificate:    &r.Certificate,
		UserDefaultTtl: SafeDuration(&r.UserDefaultTtl),
		UserMaxTtl:     SafeDuration(&r.UserMaxTtl),
	}
}

func (p *ListPrincipalsRow) ToProto() *nokkuv1.Principal {
	if p == nil {
		return nil
	}

	out := p.Principal.ToProto()
	out.UserIds = p.UserIds
	out.TeamIds = p.TeamIds
	out.ServiceAccountIds = p.ServiceAccountIds
	return out
}

func PrincipalsToProto(ps []*ListPrincipalsRow) []*nokkuv1.Principal {
	return mapSlice(ps, func(p *ListPrincipalsRow) *nokkuv1.Principal { return p.ToProto() })
}

func (t *WorkspaceToken) ToProto() *nokkuv1.Token {
	return &nokkuv1.Token{
		Id:          &t.ID,
		Kind:        &t.Kind,
		Label:       &t.Label,
		ExpiresAt:   SafeTimestamp(t.ExpiresAt),
		MaxUses:     t.MaxUses,
		Uses:        &t.Uses,
		AutoApprove: &t.AutoApprove,
		CaId:        t.CaID,
		RoleName:    t.RoleName,
		CreatedAt:   SafeTimestamp(&t.CreatedAt),
		LastUsedAt:  SafeTimestamp(t.LastUsedAt),
	}
}

func TokensToProto(ts []*WorkspaceToken) []*nokkuv1.Token {
	return mapSlice(ts, func(t *WorkspaceToken) *nokkuv1.Token { return t.ToProto() })
}
