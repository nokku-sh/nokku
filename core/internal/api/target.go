package api

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/config"
	nokkudaemon "github.com/nokku-sh/nokku/core/internal/daemon"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/namegen"
	"github.com/nokku-sh/nokku/core/internal/ssh"
)

type targetService struct {
	cfg *config.Config
}

func (s *targetService) GetTarget(
	ctx context.Context,
	req *nokkuv1.GetTargetRequest,
) (*nokkuv1.GetTargetResponse, error) {
	var target *nokkuv1.Target
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		row, err := q.GetTarget(ctx, req.GetId())
		if err != nil {
			return err
		}
		accounts, err := accountsByTarget(ctx, q, []string{row.ID})
		if err != nil {
			return err
		}
		target = row.ToProto()
		target.Accounts = accounts[row.ID]
		return nil
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.GetTargetResponse{Target: target}, nil
}

// accountsByTarget groups the login accounts of the targets, each with its grants.
func accountsByTarget(
	ctx context.Context,
	q *db.Queries,
	targetIDs []string,
) (map[string][]*nokkuv1.TargetAccount, error) {
	rows, err := q.GetTargetAccountsByTargetIDs(ctx, targetIDs)
	if err != nil {
		return nil, err
	}
	accounts := make(map[string][]*nokkuv1.TargetAccount)
	for _, p := range rows {
		targetID := p.TargetAccount.TargetID
		accounts[targetID] = append(accounts[targetID], p.ToProto())
	}
	return accounts, nil
}

func (s *targetService) CreateTarget(
	ctx context.Context,
	req *nokkuv1.CreateTargetRequest,
) (*nokkuv1.CreateTargetResponse, error) {
	if err := validateHostPublicKey(req.GetHostPublicKey()); err != nil {
		return nil, err
	}

	name := strings.TrimSpace(req.GetName())
	if name != "" {
		created, err := s.insertTarget(ctx, req, name)
		if err != nil {
			return nil, err
		}
		return created, nil
	}

	// Generated names retry with a numeric suffix on collision.
	for attempt := 0; ; attempt++ {
		generated := namegen.Generate()
		if attempt > 0 {
			generated += strconv.Itoa(attempt + 1)
		}
		created, err := s.insertTarget(ctx, req, generated)
		if err == nil {
			return created, nil
		}
		if !db.IsUniqueViolation(err) {
			return nil, err
		}
	}
}

// insertTarget returns the raw error so the caller can spot name collisions.
func (s *targetService) insertTarget(
	ctx context.Context,
	req *nokkuv1.CreateTargetRequest,
	name string,
) (*nokkuv1.CreateTargetResponse, error) {
	var result *db.Target
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		result, err = q.CreateTarget(ctx, &db.CreateTargetParams{
			Name:          name,
			Description:   req.Description,
			CaID:          req.CaId,
			Endpoints:     req.GetEndpoints(),
			Tags:          req.GetTags(),
			HostPublicKey: trimmed(req.HostPublicKey),
		})
		if err != nil {
			return err
		}

		if err = q.InsertTargetAccounts(ctx, &db.InsertTargetAccountsParams{
			TargetID:    result.ID,
			Usernames:   []string{"root"},
			MaxAccounts: db.MaxTargetAccounts,
		}); err != nil {
			return err
		}
		if err = seedTargetGrants(ctx, q, result.ID, req.GetGrants()); db.IsForeignKeyViolation(err) {
			return newError(connect.CodeInvalidArgument, "a grant names a subject that does not exist")
		}
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.CreateTargetResponse{
		Target: result.ToProto(),
	}, nil
}

// seedTargetGrants runs once, with the new target. Like a token's grants, nothing reapplies them later.
func seedTargetGrants(ctx context.Context, q *db.Queries, targetID string, grants []*nokkuv1.JoinTokenGrant) error {
	for _, g := range grants {
		account, err := q.CreateTargetAccount(ctx, &db.CreateTargetAccountParams{
			TargetID: targetID,
			Username: g.GetUsername(),
		})
		if err != nil {
			return err
		}
		subjects := map[string][]string{
			db.SubjectKindUser:           g.GetUserIds(),
			db.SubjectKindTeam:           g.GetTeamIds(),
			db.SubjectKindServiceAccount: g.GetServiceAccountIds(),
		}
		for kind, ids := range subjects {
			for _, id := range ids {
				if err := q.PutGrant(ctx, &db.PutGrantParams{
					AccountID:   account.ID,
					SubjectKind: kind,
					SubjectID:   id,
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *targetService) UpdateTarget(
	ctx context.Context,
	req *nokkuv1.UpdateTargetRequest,
) (*nokkuv1.UpdateTargetResponse, error) {
	if err := validateHostPublicKey(req.GetHostPublicKey()); err != nil {
		return nil, err
	}
	result, err := s.cfg.Conn.Tenant().UpdateTarget(ctx, &db.UpdateTargetParams{
		TargetID:    req.GetId(),
		Name:        req.Name,
		Description: req.Description,
		// An update replaces both lists. The query keeps the old one for nil.
		Endpoints:     append([]string{}, req.GetEndpoints()...),
		CaID:          req.CaId,
		Tags:          append([]string{}, req.GetTags()...),
		HostPublicKey: trimmed(req.HostPublicKey),
	})
	if err != nil {
		return nil, err
	}

	return &nokkuv1.UpdateTargetResponse{
		Target: result.ToProto(),
	}, nil
}

func (s *targetService) DeleteTarget(
	ctx context.Context,
	req *nokkuv1.DeleteTargetRequest,
) (*nokkuv1.DeleteTargetResponse, error) {
	if _, err := s.cfg.Conn.Tenant().DeleteTarget(ctx, req.GetId()); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteTargetResponse{}, nil
}

func (s *targetService) ListTargets(
	ctx context.Context,
	req *nokkuv1.ListTargetsRequest,
) (*nokkuv1.ListTargetsResponse, error) {
	var targets []*nokkuv1.Target
	var count int32
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListTargets(ctx, &db.ListTargetsParams{
			Query:    req.Query,
			DaemonID: req.DaemonId,
			CaID:     req.CaId,
			Accounts: req.GetAccounts(),
			Tags:     req.GetTags(),
			Limit:    req.Limit,
			Offset:   req.Offset,
		})
		if err != nil || len(rows) == 0 {
			return err
		}
		count = rows[0].TotalCount

		targetIDs := make([]string, 0, len(rows))
		for _, r := range rows {
			targetIDs = append(targetIDs, r.Target.ID)
		}
		accounts, err := accountsByTarget(ctx, q, targetIDs)
		if err != nil {
			return err
		}
		targets = make([]*nokkuv1.Target, 0, len(rows))
		for _, r := range rows {
			target := r.Target.ToProto()
			target.Accounts = accounts[r.Target.ID]
			targets = append(targets, target)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.ListTargetsResponse{
		Targets: targets,
		Total:   &count,
	}, nil
}

// GetTargetPrincipals feeds AuthorizedPrincipalsFile on daemonless hosts.
func (s *targetService) GetTargetPrincipals(
	ctx context.Context,
	req *nokkuv1.GetTargetPrincipalsRequest,
) (*nokkuv1.GetTargetPrincipalsResponse, error) {
	rows, err := s.cfg.Conn.Tenant().ListAccountSubjectsForTarget(ctx, req.GetTargetId())
	if err != nil {
		return nil, err
	}

	// sshd compares these as they are, see ssh.LoginPrincipal.
	principals := make([]*nokkuv1.AccountPrincipals, 0, len(rows))
	for _, r := range rows {
		certPrincipals := make([]string, 0, len(r.Ids))
		for _, id := range r.Ids {
			certPrincipals = append(certPrincipals, ssh.LoginPrincipal(id, req.GetTargetId(), r.Username))
		}
		principals = append(principals, &nokkuv1.AccountPrincipals{
			Username:       &r.Username,
			CertPrincipals: certPrincipals,
		})
	}
	return &nokkuv1.GetTargetPrincipalsResponse{Principals: principals}, nil
}

// SyncTargetUsers is the daemonless report. It never deletes accounts, so a failed report cannot lock anyone out.
func (s *targetService) SyncTargetUsers(
	ctx context.Context,
	req *nokkuv1.SyncTargetUsersRequest,
) (*nokkuv1.SyncTargetUsersResponse, error) {
	if err := validateHostPublicKey(req.GetHostPublicKey()); err != nil {
		return nil, err
	}

	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := q.InsertTargetAccounts(ctx, &db.InsertTargetAccountsParams{
			TargetID:    req.GetTargetId(),
			Usernames:   nokkudaemon.ValidUsers(req.GetUsernames()),
			MaxAccounts: db.MaxTargetAccounts,
		}); err != nil {
			return err
		}

		if err := q.ReportManualSync(ctx, &db.ReportManualSyncParams{
			TargetID:      req.GetTargetId(),
			Endpoints:     req.GetEndpoints(),
			HostPublicKey: trimmed(req.HostPublicKey),
		}); err != nil {
			return err
		}
		return q.TouchTargetSync(ctx, req.GetTargetId())
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.SyncTargetUsersResponse{}, nil
}

func (s *targetService) GetSubjectAccess(
	ctx context.Context,
	req *nokkuv1.GetSubjectAccessRequest,
) (*nokkuv1.GetSubjectAccessResponse, error) {
	// A member reads its own access. Who else holds an account is for viewers.
	caller, _ := actor.PrincipalFromContext(ctx)
	canView := callerRole(ctx) >= nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER
	if !canView && req.GetSubjectId() != caller.ID {
		return nil, db.ErrPermissionDenied
	}

	var targets []*nokkuv1.Target
	var daemons []*nokkuv1.Daemon
	var cas []*nokkuv1.CertificateAuthority

	uniqueDaemonIDs := make(map[string]struct{})
	uniqueCAIDs := make(map[string]struct{})

	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		rows, err := q.GetTargetsBySubject(ctx, req.GetSubjectId())
		if err != nil {
			return err
		}

		if len(rows) == 0 {
			return nil
		}

		targetIDs := make([]string, 0, len(rows))
		for _, r := range rows {
			targetIDs = append(targetIDs, r.ID)
			if r.DaemonID != nil {
				uniqueDaemonIDs[*r.DaemonID] = struct{}{}
			}
			if r.CaID != nil {
				uniqueCAIDs[*r.CaID] = struct{}{}
			}
		}

		uRows, err := q.ListSubjectUsernamesForTargets(ctx, &db.ListSubjectUsernamesForTargetsParams{
			TargetIds: targetIDs,
			SubjectID: req.GetSubjectId(),
		})
		if err != nil {
			return err
		}

		var accounts map[string][]*nokkuv1.TargetAccount
		if canView {
			if accounts, err = accountsByTarget(ctx, q, targetIDs); err != nil {
				return err
			}
		}

		for _, r := range rows {
			target := r.ToProto()
			target.Accounts = accounts[r.ID]
			targets = append(targets, target)
		}
		setUsernames(targets, uRows)

		if len(uniqueDaemonIDs) > 0 {
			daemonRows, err := q.GetDaemonsByIDs(ctx, slices.Collect(maps.Keys(uniqueDaemonIDs)))
			if err != nil {
				return err
			}
			for _, d := range daemonRows {
				daemons = append(daemons, &nokkuv1.Daemon{
					Id:     &d.ID,
					Name:   &d.Name,
					Online: new(db.SeenRecently(d.LastSeenAt)),
				})
			}
		}

		if len(uniqueCAIDs) > 0 {
			caRows, err := q.GetCAsByIDs(ctx, slices.Collect(maps.Keys(uniqueCAIDs)))
			if err != nil {
				return err
			}
			for _, ca := range caRows {
				cas = append(cas, ca.ToProto())
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.GetSubjectAccessResponse{
		Targets:                targets,
		CertificateAuthorities: cas,
		Daemons:                daemons,
	}, nil
}

// setUsernames fills in the accounts the subject holds on each target, and when the ones that end do.
func setUsernames(targets []*nokkuv1.Target, rows []*db.ListSubjectUsernamesForTargetsRow) {
	byID := make(map[string]*nokkuv1.Target, len(targets))
	for _, t := range targets {
		byID[t.GetId()] = t
	}
	for _, r := range rows {
		target := byID[r.TargetID]
		if target == nil {
			continue
		}
		target.Usernames = append(target.Usernames, r.Username)
		if until := r.Until(); until != nil {
			if target.UsernameExpiresAt == nil {
				target.UsernameExpiresAt = make(map[string]*timestamppb.Timestamp)
			}
			target.UsernameExpiresAt[r.Username] = timestamppb.New(*until)
		}
	}
}

func (s *targetService) GetMyAccess(
	ctx context.Context,
	_ *nokkuv1.GetMyAccessRequest,
) (*nokkuv1.GetMyAccessResponse, error) {
	p, ok := actor.PrincipalFromContext(ctx)
	if !ok || p.ID == "" {
		return nil, newError(connect.CodeUnauthenticated, "not authenticated")
	}
	//nolint:exhaustive // daemons sync through SyncDaemon
	switch p.Kind {
	case actor.KindUser, actor.KindCLI, actor.KindServiceAccount:
	default:
		return nil, newError(
			connect.CodePermissionDenied,
			"unsupported principal kind. Daemons sync through SyncDaemon.",
		)
	}

	resp := &nokkuv1.GetMyAccessResponse{}
	err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		//nolint:exhaustive // other kinds were rejected above
		switch p.Kind {
		case actor.KindUser, actor.KindCLI:
			u, err := q.GetUser(ctx, p.ID)
			if err != nil {
				return err
			}
			resp.Subject = &nokkuv1.GetMyAccessResponse_User{User: u.ToProto()}
		case actor.KindServiceAccount:
			sa, err := q.GetServiceAccount(ctx, p.ID)
			if err != nil {
				return err
			}
			resp.Subject = &nokkuv1.GetMyAccessResponse_ServiceAccount{ServiceAccount: sa.ToProto()}
		}

		rows, err := q.GetTargetsBySubject(ctx, p.ID)
		if err != nil || len(rows) == 0 {
			return err
		}

		targetIDs := make([]string, 0, len(rows))
		caIDs := make(map[string]struct{})
		for _, r := range rows {
			targetIDs = append(targetIDs, r.ID)
			if r.CaID != nil {
				caIDs[*r.CaID] = struct{}{}
			}
			resp.Targets = append(resp.Targets, r.ToProto())
		}

		// The CLI needs the accounts this subject may use, not the whole graph.
		uRows, err := q.ListSubjectUsernamesForTargets(ctx, &db.ListSubjectUsernamesForTargetsParams{
			TargetIds: targetIDs,
			SubjectID: p.ID,
		})
		if err != nil {
			return err
		}
		setUsernames(resp.GetTargets(), uRows)
		slices.SortFunc(resp.GetTargets(), func(a, b *nokkuv1.Target) int {
			return strings.Compare(a.GetName(), b.GetName())
		})

		if len(caIDs) == 0 {
			return nil
		}
		caRows, err := q.GetCAsByIDs(ctx, slices.Collect(maps.Keys(caIDs)))
		if err != nil {
			return err
		}
		for _, ca := range caRows {
			resp.CertificateAuthorities = append(resp.CertificateAuthorities, ca.ToProto())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *targetService) GetTargetFilters(
	ctx context.Context,
	_ *nokkuv1.GetTargetFiltersRequest,
) (*nokkuv1.GetTargetFiltersResponse, error) {
	var tags []string
	var accounts []string

	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		tags, err = q.GetWorkspaceTags(ctx)
		if err != nil {
			return err
		}

		accounts, err = q.GetWorkspaceAccounts(ctx)
		return err
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.GetTargetFiltersResponse{
		Tags:     tags,
		Accounts: accounts,
	}, nil
}

// GetAccessGraph counts everything in one grouped query, so the response stays small whatever the workspace size.
func (s *targetService) GetAccessGraph(
	ctx context.Context,
	req *nokkuv1.GetAccessGraphRequest,
) (*nokkuv1.GetAccessGraphResponse, error) {
	filter := cmp.Or(req.GetFilter(), &nokkuv1.AccessGraphFilter{})
	resp := &nokkuv1.GetAccessGraphResponse{}

	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		rows, err := q.GetAccessGraph(ctx, &db.GetAccessGraphParams{
			SubjectID: filter.SubjectId,
			TargetID:  filter.TargetId,
			Username:  filter.Username,
			Tag:       filter.Tag,
		})
		if err != nil {
			return err
		}

		held := make(map[string]int32)
		matched := make(map[string]int32)
		for _, r := range rows {
			switch {
			case r.BySubject && r.ByUsername:
				resp.Grants = append(resp.Grants, &nokkuv1.AccessGraphGrant{
					SubjectId: &r.SubjectID,
					Username:  &r.Username,
					Targets:   &r.Targets,
				})
			case r.ByUsername && r.ByTag:
				resp.Reach = append(resp.Reach, &nokkuv1.AccessGraphReach{
					Username: &r.Username,
					Tag:      &r.Tag,
					Targets:  &r.Targets,
				})
			case r.BySubject:
				held[r.SubjectID] = r.Targets
			case r.ByUsername:
				resp.Accounts = append(resp.Accounts, &nokkuv1.AccessGraphAccount{
					Username: &r.Username,
					Targets:  &r.Targets,
				})
			case r.ByTag:
				matched[r.Tag] = r.Targets
			default:
				resp.Targets = &r.Targets
			}
		}

		// A user who only has access through teams holds nothing, but the caller still needs their name.
		if id := filter.GetSubjectId(); id != "" {
			held[id] += 0
		}
		subjects, err := q.GetAccessGraphSubjects(ctx, slices.Collect(maps.Keys(held)))
		if err != nil {
			return err
		}
		for _, sub := range subjects {
			resp.Subjects = append(resp.Subjects, &nokkuv1.AccessGraphSubject{
				Id:          &sub.ID,
				Kind:        subjectKinds[sub.Kind].Enum(),
				Name:        &sub.Name,
				Email:       &sub.Email,
				MemberCount: &sub.MemberCount,
				Targets:     new(held[sub.ID]),
			})
		}

		tags, err := q.CountTargetsByTag(ctx)
		if err != nil {
			return err
		}
		for _, t := range tags {
			resp.Tags = append(resp.Tags, &nokkuv1.AccessGraphTag{
				Tag:     &t.Tag,
				Targets: new(matched[t.Tag]),
				Total:   &t.Total,
			})
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *targetService) ListAccessGraphTargets(
	ctx context.Context,
	req *nokkuv1.ListAccessGraphTargetsRequest,
) (*nokkuv1.ListAccessGraphTargetsResponse, error) {
	filter := cmp.Or(req.GetFilter(), &nokkuv1.AccessGraphFilter{})
	rows, err := s.cfg.Conn.Tenant().ListAccessGraphTargets(ctx, &db.ListAccessGraphTargetsParams{
		Tag:       req.GetTag(),
		FilterTag: filter.Tag,
		SubjectID: filter.SubjectId,
		TargetID:  filter.TargetId,
		Username:  filter.Username,
		Limit:     req.Limit,
		Offset:    req.Offset,
	})
	if err != nil {
		return nil, err
	}

	var total int32
	targets := make([]*nokkuv1.AccessGraphTarget, 0, len(rows))
	for _, r := range rows {
		total = r.TotalCount
		targets = append(targets, &nokkuv1.AccessGraphTarget{
			Id:      &r.ID,
			Name:    &r.Name,
			Matched: &r.Matched,
		})
	}
	return &nokkuv1.ListAccessGraphTargetsResponse{Targets: targets, Total: &total}, nil
}

func validateHostPublicKey(key string) error {
	if key == "" {
		return nil
	}
	if _, err := ssh.ParsePublicKey(key); err != nil {
		return newError(connect.CodeInvalidArgument, "invalid host public key")
	}
	return nil
}

// trimmed turns empty into nil so COALESCE keeps the stored value.
func trimmed(s *string) *string {
	if s == nil {
		return nil
	}
	v := strings.TrimSpace(*s)
	if v == "" {
		return nil
	}
	return &v
}
