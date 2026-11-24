package db

import (
	"encoding/json"
	"log/slog"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

// MaxTargetAccounts stops a host from reporting accounts without bound.
const MaxTargetAccounts = 1000

var credentialTypes = map[string]nokkuv1.CredentialType{
	"passkey": nokkuv1.CredentialType_CREDENTIAL_TYPE_PASSKEY,
	"oidc":    nokkuv1.CredentialType_CREDENTIAL_TYPE_OIDC,
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
		// Members read them too, the web offers Request access only when some are set.
		RequestableTags: w.RequestableTags,
	}
}

func (c *Credential) ToProto() *nokkuv1.AccountCredential {
	if c == nil {
		return nil
	}
	return &nokkuv1.AccountCredential{
		Id:         &c.ID,
		Type:       credentialTypes[c.Type].Enum(),
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
		DaemonId:    r.DaemonID,
		DaemonName:  &r.DaemonName,
		Username:    &r.Username,
		SubjectId:   r.SubjectID,
		SubjectName: &r.SubjectName,
		Principal:   &r.Principal,
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
		Name:        &t.Name,
		Description: t.Description,
		Tags:        t.Tags,
		CreatedAt:   SafeTimestamp(&t.CreatedAt),
		UpdatedAt:   SafeTimestamp(&t.UpdatedAt),
		ScimManaged: &t.ScimManaged,
		ScimOpen:    &t.ScimOpen,
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
		Id:            &s.ID,
		Name:          &s.Name,
		Description:   s.Description,
		Role:          &s.Role,
		Tags:          s.Tags,
		ForceCommand:  &s.ForceCommand,
		SourceAddress: &s.SourceAddress,
		LastUsedAt:    SafeTimestamp(s.LastUsedAt),
		CreatedAt:     SafeTimestamp(&s.CreatedAt),
		UpdatedAt:     SafeTimestamp(&s.UpdatedAt),
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

func (f *ServiceAccountFederation) ToProto() *nokkuv1.ServiceAccountFederation {
	return &nokkuv1.ServiceAccountFederation{
		Id:               &f.ID,
		ServiceAccountId: &f.ServiceAccountID,
		Issuer:           &f.Issuer,
		Claims:           f.Claims,
		CreatedAt:        SafeTimestamp(&f.CreatedAt),
	}
}

func ServiceAccountFederationsToProto(fs []*ServiceAccountFederation) []*nokkuv1.ServiceAccountFederation {
	return mapSlice(fs, func(f *ServiceAccountFederation) *nokkuv1.ServiceAccountFederation { return f.ToProto() })
}

func (t *Target) ToProto() *nokkuv1.Target {
	if t == nil {
		return nil
	}

	metadata := jsonMap("targets.metadata", t.Metadata)
	return &nokkuv1.Target{
		Id:            &t.ID,
		DaemonId:      t.DaemonID,
		Description:   t.Description,
		Name:          &t.Name,
		Endpoints:     t.Endpoints,
		Tags:          t.Tags,
		Metadata:      metadata,
		HostPublicKey: t.HostPublicKey,
		CreatedAt:     SafeTimestamp(&t.CreatedAt),
		UpdatedAt:     SafeTimestamp(&t.UpdatedAt),
		LastSyncAt:    SafeTimestamp(t.LastSyncAt),
		CreatedBy:     t.CreatedBy,
	}
}

// A malformed blob only logs, the row is still readable without it.
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

func (a *TargetAccount) ToProto() *nokkuv1.TargetAccount {
	if a == nil {
		return nil
	}
	return &nokkuv1.TargetAccount{
		Id:        &a.ID,
		TargetId:  &a.TargetID,
		Username:  &a.Username,
		CreatedAt: SafeTimestamp(&a.CreatedAt),
		SeenAt:    SafeTimestamp(a.SeenAt),
	}
}

func (p *GetTargetAccountsByTargetIDsRow) ToProto() *nokkuv1.TargetAccount {
	if p == nil {
		return nil
	}

	out := p.TargetAccount.ToProto()
	out.Grants = accountGrants(p.UserIds, p.TeamIds, p.ServiceAccountIds, p.ExpiringIds, p.ExpiresAt)
	return out
}

// The expiring ids and their ends come in the same order.
func accountGrants(userIDs, teamIDs, serviceAccountIDs, expiringIDs []string, at []time.Time) []*nokkuv1.Grant {
	ends := make(map[string]*timestamppb.Timestamp, len(expiringIDs))
	if len(expiringIDs) == len(at) {
		for i, id := range expiringIDs {
			ends[id] = timestamppb.New(at[i])
		}
	}
	var out []*nokkuv1.Grant
	add := func(kind nokkuv1.SubjectKind, ids []string) {
		for _, id := range ids {
			out = append(out, &nokkuv1.Grant{Subject: &nokkuv1.Subject{Id: &id, Kind: &kind}, ExpiresAt: ends[id]})
		}
	}
	add(nokkuv1.SubjectKind_SUBJECT_KIND_USER, userIDs)
	add(nokkuv1.SubjectKind_SUBJECT_KIND_TEAM, teamIDs)
	add(nokkuv1.SubjectKind_SUBJECT_KIND_SERVICE_ACCOUNT, serviceAccountIDs)
	return out
}

func (r *ListSubjectUsernamesForTargetsRow) Until() *time.Time {
	if r.ForGood {
		return nil
	}
	return &r.ExpiresAt
}

func (u *User) ToProto() *nokkuv1.User {
	if u == nil {
		return nil
	}
	return &nokkuv1.User{
		Id:          &u.ID,
		Name:        &u.Name,
		Email:       &u.Email,
		Picture:     u.Picture,
		Role:        &u.Role,
		Active:      &u.Active,
		CreatedAt:   SafeTimestamp(&u.CreatedAt),
		UpdatedAt:   SafeTimestamp(&u.UpdatedAt),
		ScimManaged: &u.ScimManaged,
	}
}

func UsersToProto(rows []*ListUsersRow) []*nokkuv1.User {
	return mapSlice(rows, func(r *ListUsersRow) *nokkuv1.User { return r.User.ToProto() })
}

// DefaultDaemonConfig must match nokkud's defaultPolicy, used until first sync. KillOnRevoke is the exception,
// nokkud reads an unset one as off.
func DefaultDaemonConfig() *nokkuv1.DaemonConfig {
	return &nokkuv1.DaemonConfig{
		RecordSessions:       new(true),
		AllowForwarding:      new(true),
		AllowAgentForwarding: new(true),
		GatewayPorts:         new(false),
		Ephemeral:            new(false),
		KillOnRevoke:         new(true),
	}
}

// EffectiveConfig reads Ephemeral off the row, a config edit can't change it.
func (d *Daemon) EffectiveConfig() *nokkuv1.DaemonConfig {
	cfg := ResolveDaemonConfig(d.Config)
	cfg.Ephemeral = new(d.RetireAfter != nil)
	return cfg
}

// ResolveDaemonConfig fills unset fields, so every reader sees the same.
func ResolveDaemonConfig(cfg *nokkuv1.DaemonConfig) *nokkuv1.DaemonConfig {
	resolved := DefaultDaemonConfig()
	if cfg != nil {
		proto.Merge(resolved, cfg)
	}
	return resolved
}

// ToProto takes the name from the daemon's target and online from the pool.
func (d *Daemon) ToProto(name string, online bool) *nokkuv1.Daemon {
	if d == nil {
		return nil
	}
	return &nokkuv1.Daemon{
		Id:         &d.ID,
		Name:       &name,
		Status:     &d.Status,
		Config:     d.EffectiveConfig(),
		Online:     &online,
		LastSeenAt: SafeTimestamp(d.LastSeenAt),
		Version:    &d.Version,
		UpdatedAt:  SafeTimestamp(&d.UpdatedAt),
		CreatedAt:  SafeTimestamp(&d.CreatedAt),
	}
}

func DaemonsToProto(rows []*ListDaemonsRow, online func(daemonID string) bool) []*nokkuv1.Daemon {
	return mapSlice(rows, func(r *ListDaemonsRow) *nokkuv1.Daemon {
		return r.Daemon.ToProto(r.Name, online(r.Daemon.ID))
	})
}

func (r *SSHCA) ToProto() *nokkuv1.CertificateAuthority {
	if r == nil {
		return nil
	}

	return &nokkuv1.CertificateAuthority{
		Id:                       &r.ID,
		UserPublicKey:            &r.UserPublicKey,
		UserPublicKeyFingerprint: new(fingerprint(r.UserPublicKey)),
		HostPublicKey:            &r.HostPublicKey,
		HostPublicKeyFingerprint: new(fingerprint(r.HostPublicKey)),
		RotatedAt:                SafeTimestamp(r.RotatedAt),
		CreatedAt:                SafeTimestamp(&r.CreatedAt),
		UpdatedAt:                SafeTimestamp(&r.UpdatedAt),
		UserTtl:                  durationpb.New(r.UserTtl),
		SourceAddress:            &r.SourceAddress,
	}
}

// fingerprint is what ssh-keygen -lf prints, empty for a key that does not parse.
func fingerprint(key string) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}

func (p *ListTargetAccountsRow) ToProto() *nokkuv1.TargetAccount {
	if p == nil {
		return nil
	}

	out := p.TargetAccount.ToProto()
	out.Grants = accountGrants(p.UserIds, p.TeamIds, p.ServiceAccountIds, p.ExpiringIds, p.ExpiresAt)
	return out
}

func (r *AccessRequestDetail) GrantedUntil() *time.Time {
	if r.Status != nokkuv1.AccessRequestStatus_ACCESS_REQUEST_STATUS_APPROVED || r.DecidedAt == nil {
		return nil
	}
	return new(r.DecidedAt.Add(r.Duration))
}

func (r *AccessRequestDetail) ToProto() *nokkuv1.AccessRequest {
	if r == nil {
		return nil
	}
	return &nokkuv1.AccessRequest{
		Id:             &r.ID,
		RequesterId:    &r.RequesterID,
		RequesterName:  &r.RequesterName,
		RequesterEmail: &r.RequesterEmail,
		TargetId:       &r.TargetID,
		TargetName:     &r.TargetName,
		Username:       &r.Username,
		Duration:       durationpb.New(r.Duration),
		Reason:         &r.Reason,
		Status:         &r.Status,
		DecidedBy:      r.DecidedBy,
		DeciderName:    &r.DeciderName,
		DecidedAt:      SafeTimestamp(r.DecidedAt),
		CreatedAt:      SafeTimestamp(&r.CreatedAt),
		GrantedUntil:   SafeTimestamp(r.GrantedUntil()),
		DecisionReason: &r.DecisionReason,
	}
}

func (r *ListAuditStreamsRow) ToProto() *nokkuv1.AuditStream {
	return &nokkuv1.AuditStream{
		Id:           &r.ID,
		Kind:         &r.Kind,
		Url:          &r.URL,
		Enabled:      &r.Enabled,
		LastSentAt:   SafeTimestamp(r.LastSentAt),
		LastError:    &r.LastError,
		FailingSince: SafeTimestamp(r.FailingSince),
		CreatedAt:    SafeTimestamp(&r.CreatedAt),
	}
}

func TargetAccountsToProto(rows []*ListTargetAccountsRow) []*nokkuv1.TargetAccount {
	return mapSlice(rows, func(r *ListTargetAccountsRow) *nokkuv1.TargetAccount { return r.ToProto() })
}

func (r *ListInvitesRow) ToProto() *nokkuv1.Invitation {
	return &nokkuv1.Invitation{
		Email:     &r.Email,
		Role:      r.Role,
		ExpiresAt: SafeTimestamp(&r.ExpiresAt),
		CreatedAt: SafeTimestamp(&r.CreatedAt),
	}
}

func InvitesToProto(rows []*ListInvitesRow) []*nokkuv1.Invitation {
	return mapSlice(rows, func(r *ListInvitesRow) *nokkuv1.Invitation { return r.ToProto() })
}

func (t *JoinToken) ToProto() *nokkuv1.JoinToken {
	out := &nokkuv1.JoinToken{
		Id:          &t.ID,
		Label:       &t.Label,
		ExpiresAt:   SafeTimestamp(t.ExpiresAt),
		MaxUses:     t.MaxUses,
		UseCount:    &t.Uses,
		AutoApprove: &t.AutoApprove,
		Tags:        t.Tags,
		Ephemeral:   new(t.RetireAfter != nil),
		CreatedAt:   SafeTimestamp(&t.CreatedAt),
		LastUsedAt:  SafeTimestamp(t.LastUsedAt),
	}
	if t.RetireAfter != nil {
		out.RetireAfter = durationpb.New(*t.RetireAfter)
	}
	return out
}

// JoinTokensToProto needs grants sorted by token and username.
func JoinTokensToProto(ts []*JoinToken, grants []*ListJoinTokenGrantsRow) []*nokkuv1.JoinToken {
	byToken := make(map[string][]*ListJoinTokenGrantsRow)
	for _, g := range grants {
		byToken[g.TokenID] = append(byToken[g.TokenID], g)
	}
	return mapSlice(ts, func(t *JoinToken) *nokkuv1.JoinToken {
		out := t.ToProto()
		out.Grants = joinTokenGrantsToProto(byToken[t.ID])
		return out
	})
}

// joinTokenGrantsToProto folds one token's rows into one grant per account.
func joinTokenGrantsToProto(rows []*ListJoinTokenGrantsRow) []*nokkuv1.JoinTokenGrant {
	var out []*nokkuv1.JoinTokenGrant
	for _, r := range rows {
		if len(out) == 0 || out[len(out)-1].GetUsername() != r.Username {
			out = append(out, &nokkuv1.JoinTokenGrant{Username: new(r.Username)})
		}
		g := out[len(out)-1]
		if r.SubjectKind != nil {
			g.Subjects = append(
				g.Subjects,
				&nokkuv1.Subject{Id: &r.SubjectID, Kind: SubjectKinds[*r.SubjectKind].Enum()},
			)
		}
	}
	return out
}

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
