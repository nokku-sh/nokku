package db

import (
	"encoding/json"
	"log/slog"

	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/util"
)

// SQL to Proto ---------------------------------------------------------------

func MapSlice[T, R any](in []T, fn func(T) R) []R {
	if in == nil {
		return nil
	}
	out := make([]R, len(in))
	for i, v := range in {
		out[i] = fn(v)
	}
	return out
}

func (u *User) ToProto() *nokkuv1.User {
	if u == nil {
		return nil
	}
	return &nokkuv1.User{
		Id:                  &u.ID,
		Name:                &u.Name,
		Username:            &u.Username,
		Email:               &u.Email,
		EmailVerified:       &u.EmailVerified,
		Picture:             u.Picture,
		EnableEmailRecovery: &u.EnableEmailRecovery,
		CreatedAt:           SafeTimestamp(&u.CreatedAt),
		UpdatedAt:           SafeTimestamp(&u.UpdatedAt),
	}
}

func (w *Workspace) ToProto() *nokkuv1.Workspace {
	if w == nil {
		return nil
	}
	return &nokkuv1.Workspace{
		Id:              &w.ID,
		Name:            &w.Name,
		Description:     w.Description,
		EnrollTokenHash: new(w.EnrollTokenHash.Hash()),
		EnrollExpiresAt: SafeTimestamp(w.EnrollExpiresAt),
		InviteTokenHash: new(w.InviteTokenHash.Hash()),
		InviteExpiresAt: SafeTimestamp(w.InviteExpiresAt),
		Settings:        w.Settings,
		CreatedBy:       &w.CreatedBy,
		CreatedAt:       SafeTimestamp(&w.CreatedAt),
		UpdatedAt:       SafeTimestamp(&w.UpdatedAt),
	}
}

func ListWorkspacesToProto(ws []*Workspace) []*nokkuv1.Workspace {
	return MapSlice(
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

func (w *GetWorkspaceMemberRow) ToProto() *nokkuv1.WorkspaceMember {
	if w == nil {
		return nil
	}
	return &nokkuv1.WorkspaceMember{
		Id:            &w.ID,
		WorkspaceId:   &w.WorkspaceID,
		Name:          &w.Name,
		Username:      &w.Username,
		Email:         &w.Email,
		EmailVerified: &w.EmailVerified,
		Picture:       w.Picture,
		RoleName:      &w.RoleName,
		CreatedAt:     SafeTimestamp(&w.CreatedAt),
		UpdatedAt:     SafeTimestamp(&w.UpdatedAt),
	}
}

func (w *ListWorkspaceMembersRow) ToProto() *nokkuv1.WorkspaceMember {
	if w == nil {
		return nil
	}
	return &nokkuv1.WorkspaceMember{
		Id:            &w.ID,
		WorkspaceId:   &w.WorkspaceID,
		Name:          &w.Name,
		Username:      &w.Username,
		Email:         &w.Email,
		EmailVerified: &w.EmailVerified,
		Picture:       w.Picture,
		RoleName:      &w.RoleName,
		CreatedAt:     SafeTimestamp(&w.CreatedAt),
		UpdatedAt:     SafeTimestamp(&w.UpdatedAt),
	}
}

func WorkspaceMembersToProto(ws []*ListWorkspaceMembersRow) []*nokkuv1.WorkspaceMember {
	return MapSlice(
		ws,
		func(w *ListWorkspaceMembersRow) *nokkuv1.WorkspaceMember { return w.ToProto() },
	)
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

func (r *ListTeamsRow) ToProto() *nokkuv1.Team {
	if r == nil {
		return nil
	}
	return (&Team{
		ID:          r.ID,
		WorkspaceID: r.WorkspaceID,
		Name:        r.Name,
		Description: r.Description,
		Tags:        r.Tags,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}).ToProto()
}

func TeamsToProto(rows []*ListTeamsRow) []*nokkuv1.Team {
	return MapSlice(rows, func(r *ListTeamsRow) *nokkuv1.Team { return r.ToProto() })
}

func (t *ListTeamMembersRow) ToProto() *nokkuv1.WorkspaceMember {
	if t == nil {
		return nil
	}
	return &nokkuv1.WorkspaceMember{
		Id:            &t.ID,
		WorkspaceId:   &t.WorkspaceID,
		Name:          &t.Name,
		Username:      &t.Username,
		Email:         &t.Email,
		EmailVerified: &t.EmailVerified,
		Picture:       t.Picture,
		CreatedAt:     SafeTimestamp(&t.CreatedAt),
	}
}

func TeamMembersToProto(ts []*ListTeamMembersRow) []*nokkuv1.WorkspaceMember {
	return MapSlice(
		ts,
		func(t *ListTeamMembersRow) *nokkuv1.WorkspaceMember { return t.ToProto() },
	)
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

func (r *ListServiceAccountsRow) ToProto() *nokkuv1.ServiceAccount {
	if r == nil {
		return nil
	}

	return (&ServiceAccount{
		ID:          r.ID,
		WorkspaceID: r.WorkspaceID,
		Name:        r.Name,
		Description: r.Description,
		RoleName:    r.RoleName,
		ExpiresAt:   r.ExpiresAt,
		Tags:        r.Tags,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}).ToProto()
}

func ServiceAccountsToProto(rows []*ListServiceAccountsRow) []*nokkuv1.ServiceAccount {
	return MapSlice(
		rows,
		func(r *ListServiceAccountsRow) *nokkuv1.ServiceAccount { return r.ToProto() },
	)
}

func (t *Target) ToProto() *nokkuv1.Target {
	if t == nil {
		return nil
	}

	metadata := make(map[string]string)
	_ = json.Unmarshal(t.Metadata, &metadata)
	return &nokkuv1.Target{
		Id:          &t.ID,
		WorkspaceId: &t.WorkspaceID,
		DaemonId:    t.DaemonID,
		CaId:        t.CaID,
		Description: t.Description,
		Name:        &t.Name,
		Endpoints:   t.Endpoints,
		Tags:        t.Tags,
		Metadata:    metadata,
		CreatedAt:   SafeTimestamp(&t.CreatedAt),
		UpdatedAt:   SafeTimestamp(&t.UpdatedAt),
	}
}

func (r *ListTargetsRow) ToProto() *nokkuv1.Target {
	if r == nil {
		return nil
	}
	return (&Target{
		ID:          r.ID,
		WorkspaceID: r.WorkspaceID,
		CaID:        r.CaID,
		DaemonID:    r.DaemonID,
		Name:        r.Name,
		Description: r.Description,
		Endpoints:   r.Endpoints,
		Tags:        r.Tags,
		Metadata:    r.Metadata,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}).ToProto()
}

func ListTargetsToProto(rows []*ListTargetsRow) []*nokkuv1.Target {
	return MapSlice(rows, func(r *ListTargetsRow) *nokkuv1.Target { return r.ToProto() })
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
	return &nokkuv1.Principal{
		Id:                &p.ID,
		TargetId:          &p.TargetID,
		Username:          &p.Username,
		CreatedAt:         SafeTimestamp(&p.CreatedAt),
		UserIds:           p.UserIds,
		TeamIds:           p.TeamIds,
		ServiceAccountIds: p.ServiceAccountIds,
	}
}

func (p *GetPrincipalsRow) ToProto() *nokkuv1.Principal {
	if p == nil {
		return nil
	}
	return &nokkuv1.Principal{
		Id:                &p.ID,
		TargetId:          &p.TargetID,
		Username:          &p.Username,
		CreatedAt:         SafeTimestamp(&p.CreatedAt),
		UserIds:           p.UserIds,
		TeamIds:           p.TeamIds,
		ServiceAccountIds: p.ServiceAccountIds,
	}
}

func (d *Daemon) ToProto() *nokkuv1.Daemon {
	if d == nil {
		return nil
	}
	metadata := make(map[string]string)
	_ = json.Unmarshal(d.Metadata, &metadata)
	return &nokkuv1.Daemon{
		Id:          &d.ID,
		WorkspaceId: &d.WorkspaceID,
		Name:        &d.Name,
		Status:      &d.Status,
		Config:      d.Config,
		Online:      &d.Online,
		Metadata:    metadata,
		UpdatedAt:   SafeTimestamp(&d.UpdatedAt),
		CreatedAt:   SafeTimestamp(&d.CreatedAt),
	}
}

func (r *ListDaemonsRow) ToProto() *nokkuv1.Daemon {
	if r == nil {
		return nil
	}
	return (&Daemon{
		ID:          r.ID,
		WorkspaceID: r.WorkspaceID,
		Name:        r.Name,
		Status:      r.Status,
		Online:      r.Online,
		Config:      r.Config,
		Metadata:    r.Metadata,
		UpdatedAt:   r.UpdatedAt,
		CreatedAt:   r.CreatedAt,
	}).ToProto()
}

func DaemonsToProto(rows []*ListDaemonsRow) []*nokkuv1.Daemon {
	return MapSlice(rows, func(r *ListDaemonsRow) *nokkuv1.Daemon { return r.ToProto() })
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
	return MapSlice(
		cas,
		func(rca *CertificateAuthority) *nokkuv1.CertificateAuthority { return rca.ToProto() },
	)
}

func (d *WorkspaceDomain) ToProto() *nokkuv1.WorkspaceDomain {
	if d == nil {
		return nil
	}
	return &nokkuv1.WorkspaceDomain{
		Domain:            &d.Domain,
		WorkspaceId:       &d.WorkspaceID,
		VerificationToken: &d.VerificationToken,
		VerifiedAt:        SafeTimestamp(d.VerifiedAt),
		CreatedAt:         SafeTimestamp(&d.CreatedAt),
		UpdatedAt:         SafeTimestamp(&d.UpdatedAt),
	}
}

func WorkspaceDomainsToProto(ds []*WorkspaceDomain) []*nokkuv1.WorkspaceDomain {
	return MapSlice(ds, func(d *WorkspaceDomain) *nokkuv1.WorkspaceDomain { return d.ToProto() })
}

func (o *OidcProvider) ToProto() *nokkuv1.OIDCProvider {
	if o == nil {
		return nil
	}
	return &nokkuv1.OIDCProvider{
		WorkspaceId:          &o.WorkspaceID,
		Name:                 &o.Name,
		IssuerUrl:            o.IssuerURL,
		ClientId:             o.ClientID,
		Scopes:               o.Scopes,
		EmailClaim:           &o.EmailClaim,
		NameClaim:            &o.NameClaim,
		UsernameClaim:        &o.UsernameClaim,
		PictureClaim:         &o.PictureClaim,
		EnforceSso:           &o.EnforceSso,
		AllowJitProvisioning: &o.AllowJitProvisioning,
		UsePkce:              &o.UsePkce,
		IsActive:             &o.IsActive,
		CreatedAt:            SafeTimestamp(&o.CreatedAt),
		UpdatedAt:            SafeTimestamp(&o.UpdatedAt),
	}
}

func (s *SamlProvider) ToProto() *nokkuv1.SAMLProvider {
	if s == nil {
		return nil
	}
	return &nokkuv1.SAMLProvider{
		WorkspaceId:          &s.WorkspaceID,
		Name:                 &s.Name,
		MetadataUrl:          s.MetadataURL,
		EmailAttribute:       &s.EmailAttribute,
		NameAttribute:        &s.NameAttribute,
		UsernameAttribute:    &s.UsernameAttribute,
		PictureAttribute:     s.PictureAttribute,
		EnforceSso:           &s.EnforceSso,
		AllowJitProvisioning: &s.AllowJitProvisioning,
		IsActive:             &s.IsActive,
		CreatedAt:            SafeTimestamp(&s.CreatedAt),
		UpdatedAt:            SafeTimestamp(&s.UpdatedAt),
	}
}

func (p *ListPrincipalsRow) ToProto() *nokkuv1.Principal {
	if p == nil {
		return nil
	}
	return &nokkuv1.Principal{
		Id:                &p.ID,
		TargetId:          &p.TargetID,
		Username:          &p.Username,
		CreatedAt:         SafeTimestamp(&p.CreatedAt),
		UserIds:           p.UserIds,
		TeamIds:           p.TeamIds,
		ServiceAccountIds: p.ServiceAccountIds,
	}
}

func ListPrincipalsToProto(ps []*ListPrincipalsRow) []*nokkuv1.Principal {
	return MapSlice(ps, func(p *ListPrincipalsRow) *nokkuv1.Principal { return p.ToProto() })
}
