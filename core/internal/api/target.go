package api

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/config"
	nokkudaemon "github.com/nokku-sh/nokku/core/internal/daemon"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/namegen"
	"github.com/nokku-sh/nokku/core/internal/ssh"
)

var targetStatuses = map[nokkuv1.TargetStatus]*string{
	nokkuv1.TargetStatus_TARGET_STATUS_UNSPECIFIED: nil,
	nokkuv1.TargetStatus_TARGET_STATUS_PENDING:     new("pending"),
	nokkuv1.TargetStatus_TARGET_STATUS_ONLINE:      new("online"),
	nokkuv1.TargetStatus_TARGET_STATUS_OFFLINE:     new("offline"),
	nokkuv1.TargetStatus_TARGET_STATUS_MANUAL:      new("manual"),
}

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
		return withDaemons(ctx, q, s.cfg.Pool, []*nokkuv1.Target{target})
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.GetTargetResponse{Target: target}, nil
}

// withDaemons puts each server's daemon on it, live state included.
func withDaemons(ctx context.Context, q *db.Queries, pool *nokkudaemon.Pool, targets []*nokkuv1.Target) error {
	var ids []string
	for _, t := range targets {
		if t.DaemonId != nil {
			ids = append(ids, t.GetDaemonId())
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := q.GetDaemonsByIDs(ctx, ids)
	if err != nil {
		return err
	}
	daemons := make(map[string]*nokkuv1.Daemon, len(rows))
	for _, d := range rows {
		daemons[d.Daemon.ID] = liveDaemon(pool, &d.Daemon, d.Name)
	}
	for _, t := range targets {
		t.Daemon = daemons[t.GetDaemonId()]
	}
	return nil
}

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
	// A cookie adds a server by name only, or an old one could put a deleted server's name on another host.
	caller, _ := actor.PrincipalFromContext(ctx)
	if caller.Kind == actor.KindUser && (len(req.GetEndpoints()) > 0 || req.GetHostPublicKey() != "") {
		return nil, connect.NewError(
			connect.CodePermissionDenied,
			"add the server by name, then run nk sync on it or set its address in the settings",
		)
	}

	name := strings.TrimSpace(req.GetName())
	if name != "" {
		created, err := s.insertTarget(ctx, req, name)
		if err != nil {
			return nil, err
		}
		return created, nil
	}

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
	var createdBy *string
	if caller, ok := actor.PrincipalFromContext(ctx); ok && caller.ID != "" {
		createdBy = &caller.ID
	}
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		result, err = q.CreateTarget(ctx, &db.CreateTargetParams{
			Name:          name,
			Description:   req.Description,
			Endpoints:     req.GetEndpoints(),
			Tags:          req.GetTags(),
			HostPublicKey: trimmed(req.HostPublicKey),
			CreatedBy:     createdBy,
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
			return connect.NewError(connect.CodeInvalidArgument, "a grant names a subject that does not exist")
		}
		return err
	}); err != nil {
		return nil, err
	}
	// A generated name is only known now.
	audit.SetTarget(ctx, result.ID)
	audit.Set(ctx, "name", result.Name)
	return &nokkuv1.CreateTargetResponse{
		Target: result.ToProto(),
	}, nil
}

// seedTargetGrants runs once. Like a token's grants, nothing reapplies them.
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

// ownTarget keeps a service account to the servers it added, a leaked key must not repoint someone else's.
func ownTarget(caller actor.Principal, target *db.Target) error {
	if caller.Kind != actor.KindServiceAccount || addedBy(target, caller) {
		return nil
	}
	return connect.NewError(
		connect.CodePermissionDenied,
		"a service account can only sync the servers it added itself",
	)
}

func addedBy(target *db.Target, caller actor.Principal) bool {
	return target.CreatedBy != nil && *target.CreatedBy == caller.ID
}

// repinTarget lets only whoever added a server replace its pinned host key, the first pin stays open.
func repinTarget(caller actor.Principal, target *db.Target, req *nokkuv1.SyncTargetUsersRequest) error {
	key, pinned := strings.TrimSpace(req.GetHostPublicKey()), target.HostPublicKey
	if key == "" || pinned == nil || key == *pinned || addedBy(target, caller) {
		return nil
	}
	return connect.NewError(
		connect.CodePermissionDenied,
		"only whoever added this server can pin a new host key with nk sync. "+
			"Anyone else forgets the host key in the web app, in the server's settings",
	)
}

func (s *targetService) UpdateTarget(
	ctx context.Context,
	req *nokkuv1.UpdateTargetRequest,
) (*nokkuv1.UpdateTargetResponse, error) {
	named, err := applyMask(req, req.GetUpdateMask())
	if err != nil {
		return nil, err
	}
	params := &db.UpdateTargetParams{
		TargetID:    req.GetId(),
		Name:        req.Name,
		Description: req.Description,
		Endpoints:   maskedList(named("endpoints"), req.GetEndpoints()),
		Tags:        maskedList(named("tags"), req.GetTags()),
	}
	result, err := s.cfg.Conn.Tenant().UpdateTarget(ctx, params)
	if err != nil {
		return nil, err
	}
	audit.Set(ctx, "name", result.Name)

	return &nokkuv1.UpdateTargetResponse{
		Target: result.ToProto(),
	}, nil
}

func (s *targetService) DeleteTarget(
	ctx context.Context,
	req *nokkuv1.DeleteTargetRequest,
) (*nokkuv1.DeleteTargetResponse, error) {
	// A nokkud server goes with its daemon, the delete cascades to it.
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		target, err := q.GetTarget(ctx, req.GetId())
		if err != nil {
			return err
		}
		audit.Set(ctx, "name", target.Name)
		// A browser needed a fresh sign-in to get here. A stolen nk session or key must not delete the fleet.
		if caller, _ := actor.PrincipalFromContext(ctx); caller.Kind != actor.KindUser && !addedBy(target, caller) {
			return connect.NewError(
				connect.CodePermissionDenied,
				"only whoever added this server deletes it with nk rm. Anyone else deletes it in the web app",
			)
		}
		if target.DaemonID != nil {
			_, err = q.DeleteDaemon(ctx, *target.DaemonID)
			return err
		}
		_, err = q.DeleteTarget(ctx, target.ID)
		return err
	}); err != nil {
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
	// Only the online and offline filters read the pool.
	var connected []string
	if st := req.GetStatus(); st == nokkuv1.TargetStatus_TARGET_STATUS_ONLINE ||
		st == nokkuv1.TargetStatus_TARGET_STATUS_OFFLINE {
		connected = s.cfg.Pool.ConnectedIn(actor.WorkspaceIDFromContext(ctx))
	}
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListTargets(ctx, &db.ListTargetsParams{
			Query:     req.Query,
			DaemonID:  req.DaemonId,
			Accounts:  req.GetAccounts(),
			Tags:      req.GetTags(),
			Ids:       req.GetIds(),
			Status:    targetStatuses[req.GetStatus()],
			Connected: connected,
			Limit:     req.Limit,
			Offset:    req.Offset,
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
		return withDaemons(ctx, q, s.cfg.Pool, targets)
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.ListTargetsResponse{
		Targets: targets,
		Total:   &count,
	}, nil
}

// SyncTargetUsers never deletes accounts, a bad report can't lock anyone out.
func (s *targetService) SyncTargetUsers(
	ctx context.Context,
	req *nokkuv1.SyncTargetUsersRequest,
) (*nokkuv1.SyncTargetUsersResponse, error) {
	if err := validateHostPublicKey(req.GetHostPublicKey()); err != nil {
		return nil, err
	}
	caller, _ := actor.PrincipalFromContext(ctx)

	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		// Locked, or two reports that both saw no pin would both pin.
		target, err := q.LockTarget(ctx, req.GetTargetId())
		if err != nil {
			return err
		}
		if target.DaemonID != nil {
			return connect.NewError(connect.CodeInvalidArgument, "this server runs the daemon, which reports for it")
		}
		if err := ownTarget(caller, target); err != nil {
			return err
		}
		if err := repinTarget(caller, target, req); err != nil {
			return err
		}
		// The stamp says the host has the current key, so check it under the lock.
		ca, err := q.GetWorkspaceCAForShare(ctx)
		if err != nil {
			return err
		}
		if ca.UserPublicKey != req.GetUserCaPublicKey() {
			return connect.NewError(
				connect.CodeFailedPrecondition,
				"the certificate authority was rolled over during this sync",
			)
		}
		if err := q.InsertTargetAccounts(ctx, &db.InsertTargetAccountsParams{
			TargetID:    req.GetTargetId(),
			Usernames:   nokkudaemon.ValidUsers(req.GetUsernames()),
			MaxAccounts: db.MaxTargetAccounts,
		}); err != nil {
			return err
		}

		if err := q.ReportManualSync(ctx, &db.ReportManualSyncParams{
			TargetID:      req.GetTargetId(),
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

// ForgetHostKey leaves the server without a pin, so the next nk sync is a first one and anyone's may pin again.
func (s *targetService) ForgetHostKey(
	ctx context.Context,
	req *nokkuv1.ForgetHostKeyRequest,
) (*nokkuv1.ForgetHostKeyResponse, error) {
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		target, err := q.GetTarget(ctx, req.GetId())
		if err != nil {
			return err
		}
		audit.Set(ctx, "name", target.Name)
		if target.DaemonID != nil {
			return connect.NewError(
				connect.CodeFailedPrecondition,
				"a server with the daemon has no pinned host key, the certificate authority vouches for it",
			)
		}
		return q.ForgetHostKey(ctx, target.ID)
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.ForgetHostKeyResponse{}, nil
}

func (s *targetService) GetSubjectAccess(
	ctx context.Context,
	req *nokkuv1.GetSubjectAccessRequest,
) (*nokkuv1.GetSubjectAccessResponse, error) {
	// Anyone reads their own access. Who else holds an account is for viewers.
	caller, _ := actor.PrincipalFromContext(ctx)
	subjectID := cmp.Or(req.GetSubjectId(), caller.ID)
	canView := callerRole(ctx) >= nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER
	if !canView && subjectID != caller.ID {
		return nil, db.ErrPermissionDenied
	}

	res := &nokkuv1.GetSubjectAccessResponse{}
	var targets []*nokkuv1.Target
	var daemons []*nokkuv1.Daemon

	uniqueDaemonIDs := make(map[string]struct{})

	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := setSubject(ctx, q, res, subjectID); err != nil {
			return err
		}
		rows, err := q.GetTargetsBySubject(ctx, subjectID)
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
		}

		uRows, err := q.ListSubjectUsernamesForTargets(ctx, &db.ListSubjectUsernamesForTargetsParams{
			TargetIds: targetIDs,
			SubjectID: subjectID,
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
		slices.SortFunc(targets, func(a, b *nokkuv1.Target) int { return strings.Compare(a.GetName(), b.GetName()) })

		if len(uniqueDaemonIDs) > 0 {
			daemonRows, err := q.GetDaemonsByIDs(ctx, slices.Collect(maps.Keys(uniqueDaemonIDs)))
			if err != nil {
				return err
			}
			for _, d := range daemonRows {
				daemons = append(daemons, &nokkuv1.Daemon{
					Id:     &d.Daemon.ID,
					Name:   &d.Name,
					Online: new(s.cfg.Pool.IsConnected(d.Daemon.ID)),
					// Only whether it records, so people know before they log in.
					Config: &nokkuv1.DaemonConfig{
						RecordSessions: new(db.ResolveDaemonConfig(d.Daemon.Config).GetRecordSessions()),
					},
				})
			}
		}

		ca, err := q.GetWorkspaceCA(ctx)
		if err != nil {
			return err
		}
		res.CertificateAuthority = ca.ToProto()
		return nil
	}); err != nil {
		return nil, err
	}

	res.Targets, res.Daemons = targets, daemons
	return res, nil
}

// setSubject finds a person or service account. A team is left out.
func setSubject(ctx context.Context, q *db.Queries, res *nokkuv1.GetSubjectAccessResponse, subjectID string) error {
	// A service account asking about itself skips the user lookup.
	caller, _ := actor.PrincipalFromContext(ctx)
	if caller.ID != subjectID || caller.Kind != actor.KindServiceAccount {
		u, err := q.GetUser(ctx, subjectID)
		if err == nil {
			res.Subject = &nokkuv1.GetSubjectAccessResponse_User{User: u.ToProto()}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}
	sa, err := q.GetServiceAccount(ctx, subjectID)
	if err == nil {
		res.Subject = &nokkuv1.GetSubjectAccessResponse_ServiceAccount{ServiceAccount: sa.ToProto()}
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}

// setUsernames also sets when accounts end, and why they let nobody in today.
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
		switch {
		case !r.UserOk:
			target.Blocked = nokkuv1.AccessBlock_ACCESS_BLOCK_USER_INACTIVE.Enum()
		case !r.DaemonOk:
			target.Blocked = nokkuv1.AccessBlock_ACCESS_BLOCK_DAEMON_NOT_APPROVED.Enum()
		}
		if until := r.Until(); until != nil {
			if target.UsernameExpiresAt == nil {
				target.UsernameExpiresAt = make(map[string]*timestamppb.Timestamp)
			}
			target.UsernameExpiresAt[r.Username] = timestamppb.New(*until)
		}
	}
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

// GetAccessGraph counts in one grouped query, so the response stays small.
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

		// A team-only user holds nothing, the caller still needs the name.
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
		return connect.NewError(connect.CodeInvalidArgument, "invalid host public key")
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
