package db

import (
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
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

// jsonMap logs a malformed blob and returns an empty map, the row is still readable without it.
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
		LastSyncAt:    SafeTimestamp(t.LastSyncAt),
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
		SeenAt:    SafeTimestamp(a.SeenAt),
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
	out.ExpiresAt = expiries(p.ExpiringIds, p.ExpiresAt)
	return out
}

// expiries pairs the two arrays a grant query returns in the same order.
func expiries(ids []string, at []time.Time) map[string]*timestamppb.Timestamp {
	if len(ids) == 0 || len(ids) != len(at) {
		return nil
	}
	out := make(map[string]*timestamppb.Timestamp, len(ids))
	for i, id := range ids {
		out[id] = timestamppb.New(at[i])
	}
	return out
}

// Until is when the access ends, nil when it is for good.
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
		ScimManaged: new(u.ScimExternalID != nil),
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

// DefaultDaemonConfig must match nokkud's DefaultPolicy, which covers the time before its first sync.
func DefaultDaemonConfig() *nokkuv1.DaemonConfig {
	return &nokkuv1.DaemonConfig{
		RecordSessions:       new(true),
		AllowForwarding:      new(true),
		AllowAgentForwarding: new(true),
		GatewayPorts:         new(false),
		Ephemeral:            new(false),
	}
}

// EffectiveConfig is what the daemon and the UI see. Ephemeral comes from the row, not the stored config,
// so an admin's config edit cannot change it.
func (d *Daemon) EffectiveConfig() *nokkuv1.DaemonConfig {
	cfg := ResolveDaemonConfig(d.Config)
	cfg.Ephemeral = new(d.RetireAfter != nil)
	// The workspace sets it for every daemon, see daemon.Sync.
	cfg.IdleTimeout = nil
	return cfg
}

// ResolveDaemonConfig fills unset fields, so the daemon, the API and the UI never read one differently.
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
		Config:     d.EffectiveConfig(),
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

	return &nokkuv1.CertificateAuthority{
		Id:                    &r.ID,
		Name:                  &r.Name,
		Description:           r.Description,
		PublicKey:             &r.PublicKey,
		HostPublicKey:         &r.HostPublicKey,
		RotatedAt:             SafeTimestamp(&r.RotatedAt),
		IsActive:              &r.IsActive,
		IsDefault:             &r.IsDefault,
		CreatedAt:             SafeTimestamp(&r.CreatedAt),
		UpdatedAt:             SafeTimestamp(&r.UpdatedAt),
		UserDefaultTtl:        durationpb.New(r.UserDefaultTtl),
		UserMaxTtl:            durationpb.New(r.UserMaxTtl),
		ForceCommand:          &r.ForceCommand,
		SourceAddress:         &r.SourceAddress,
		HostDefaultTtl:        durationpb.New(r.HostDefaultTtl),
		HostMaxTtl:            durationpb.New(r.HostMaxTtl),
		PreviousPublicKey:     r.PreviousPublicKey,
		PreviousHostPublicKey: r.PreviousHostPublicKey,
		PreviousTrustedUntil:  SafeTimestamp(r.PreviousTrustedUntil),
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
		Id:                    &r.ID,
		Name:                  &r.Name,
		PublicKey:             &r.PublicKey,
		HostPublicKey:         &r.HostPublicKey,
		RotatedAt:             SafeTimestamp(&r.RotatedAt),
		IsDefault:             &r.IsDefault,
		UserDefaultTtl:        durationpb.New(r.UserDefaultTtl),
		UserMaxTtl:            durationpb.New(r.UserMaxTtl),
		PreviousPublicKey:     r.PreviousPublicKey,
		PreviousHostPublicKey: r.PreviousHostPublicKey,
		PreviousTrustedUntil:  SafeTimestamp(r.PreviousTrustedUntil),
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
	out.ExpiresAt = expiries(p.ExpiringIds, p.ExpiresAt)
	return out
}

func (h *LegalHold) ToProto() *nokkuv1.LegalHold {
	if h == nil {
		return nil
	}
	return &nokkuv1.LegalHold{
		Id:        &h.ID,
		Reason:    &h.Reason,
		StartsAt:  SafeTimestamp(&h.StartsAt),
		EndsAt:    SafeTimestamp(h.EndsAt),
		CreatedBy: h.CreatedBy,
		CreatedAt: SafeTimestamp(&h.CreatedAt),
	}
}

func LegalHoldsToProto(rows []*LegalHold) []*nokkuv1.LegalHold {
	return mapSlice(rows, func(h *LegalHold) *nokkuv1.LegalHold { return h.ToProto() })
}

// The status and kind columns hold the enum names in lower case, without the prefix.
const (
	accessRequestStatusPrefix = "ACCESS_REQUEST_STATUS_"
	auditStreamKindPrefix     = "AUDIT_STREAM_KIND_"
)

// AccessRequestStatus is the column value of status, empty for none.
func AccessRequestStatus(status nokkuv1.AccessRequestStatus) string {
	if status == nokkuv1.AccessRequestStatus_ACCESS_REQUEST_STATUS_UNSPECIFIED {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(status.String(), accessRequestStatusPrefix))
}

// GrantedUntil is when an approved request's access ends, nil for any other.
func (r *AccessRequestDetail) GrantedUntil() *time.Time {
	if r.Status != AccessRequestStatus(nokkuv1.AccessRequestStatus_ACCESS_REQUEST_STATUS_APPROVED) ||
		r.DecidedAt == nil {
		return nil
	}
	return new(r.DecidedAt.Add(r.Duration))
}

func (r *AccessRequestDetail) ToProto() *nokkuv1.AccessRequest {
	if r == nil {
		return nil
	}
	status := nokkuv1.AccessRequestStatus(
		nokkuv1.AccessRequestStatus_value[accessRequestStatusPrefix+strings.ToUpper(r.Status)],
	)
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
		Status:         &status,
		DecidedBy:      r.DecidedBy,
		DeciderName:    &r.DeciderName,
		DecidedAt:      SafeTimestamp(r.DecidedAt),
		CreatedAt:      SafeTimestamp(&r.CreatedAt),
		GrantedUntil:   SafeTimestamp(r.GrantedUntil()),
	}
}

// AuditStreamKind is the column value of kind.
func AuditStreamKind(kind nokkuv1.AuditStreamKind) string {
	return strings.ToLower(strings.TrimPrefix(kind.String(), auditStreamKindPrefix))
}

func (r *ListAuditStreamsRow) ToProto() *nokkuv1.AuditStream {
	kind := nokkuv1.AuditStreamKind(nokkuv1.AuditStreamKind_value[auditStreamKindPrefix+strings.ToUpper(r.Kind)])
	return &nokkuv1.AuditStream{
		Id:           &r.ID,
		Kind:         &kind,
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

func (t *JoinToken) ToProto() *nokkuv1.JoinToken {
	out := &nokkuv1.JoinToken{
		Id:          &t.ID,
		Kind:        &t.Kind,
		Label:       &t.Label,
		ExpiresAt:   SafeTimestamp(t.ExpiresAt),
		MaxUses:     t.MaxUses,
		Uses:        &t.Uses,
		AutoApprove: &t.AutoApprove,
		CaId:        t.CaID,
		Role:        t.Role,
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

// JoinTokensToProto attaches each token's grants. The rows come sorted by token and username.
func JoinTokensToProto(ts []*JoinToken, grants []*ListJoinTokenGrantsRow) []*nokkuv1.JoinToken {
	byToken := make(map[string][]*ListJoinTokenGrantsRow)
	for _, g := range grants {
		byToken[g.TokenID] = append(byToken[g.TokenID], g)
	}
	return mapSlice(ts, func(t *JoinToken) *nokkuv1.JoinToken {
		out := t.ToProto()
		out.Grants = JoinTokenGrantsToProto(byToken[t.ID])
		return out
	})
}

// JoinTokenGrantsToProto folds one token's rows into one grant per account.
func JoinTokenGrantsToProto(rows []*ListJoinTokenGrantsRow) []*nokkuv1.JoinTokenGrant {
	var out []*nokkuv1.JoinTokenGrant
	for _, r := range rows {
		if len(out) == 0 || out[len(out)-1].GetUsername() != r.Username {
			out = append(out, &nokkuv1.JoinTokenGrant{Username: new(r.Username)})
		}
		g := out[len(out)-1]
		if r.SubjectKind == nil {
			continue
		}
		switch *r.SubjectKind {
		case SubjectKindUser:
			g.UserIds = append(g.UserIds, r.SubjectID)
		case SubjectKindTeam:
			g.TeamIds = append(g.TeamIds, r.SubjectID)
		case SubjectKindServiceAccount:
			g.ServiceAccountIds = append(g.ServiceAccountIds, r.SubjectID)
		}
	}
	return out
}
