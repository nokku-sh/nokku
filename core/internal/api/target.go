package api

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/audit"
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
	cfg *app.Config
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
	if len(targets) == 0 {
		return nil
	}
	ids := make([]string, len(targets))
	for i, t := range targets {
		ids[i] = t.GetId()
	}
	rows, err := q.GetDaemonsByIDs(ctx, ids)
	if err != nil {
		return err
	}
	daemons := make(map[string]*nokkuv1.Daemon, len(rows))
	for _, d := range rows {
		daemons[d.Daemon.TargetID] = liveDaemon(pool, &d.Daemon, d.Name)
	}
	for _, t := range targets {
		t.Daemon = daemons[t.GetId()]
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
		return s.insertTarget(ctx, req, name)
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
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		result, err = q.CreateTarget(ctx, &db.CreateTargetParams{
			Name:          name,
			Description:   req.GetDescription(),
			Endpoints:     req.GetEndpoints(),
			Tags:          req.GetTags(),
			HostPublicKey: strings.TrimSpace(req.GetHostPublicKey()),
			CreatedBy:     callerID(ctx),
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
		for _, subject := range g.GetSubjects() {
			if err := q.PutGrants(ctx, &db.PutGrantsParams{
				AccountIds:  []string{account.ID},
				SubjectKind: subjectKind(subject.GetKind()),
				SubjectID:   subject.GetId(),
			}); err != nil {
				return err
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

// A comment is no part of what ssh checks.
func sameHostKey(a, b string) bool {
	key := func(line string) string {
		f := strings.Fields(line)
		return strings.Join(f[:min(2, len(f))], " ")
	}
	return key(a) == key(b)
}

// repinTarget lets only whoever added a server replace its pinned host key, the first pin stays open.
func repinTarget(caller actor.Principal, target *db.Target, req *nokkuv1.SyncTargetUsersRequest) error {
	key, pinned := strings.TrimSpace(req.GetHostPublicKey()), target.HostPublicKey
	if key == "" || pinned == "" || sameHostKey(key, pinned) || addedBy(target, caller) {
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
		Description: req.Description,
		Tags:        maskedList(named("tags"), req.GetTags()),
	}
	result, err := s.cfg.Conn.Tenant().UpdateTarget(ctx, params)
	if err != nil {
		return nil, err
	}
	audit.Set(ctx, "name", result.Name)

	return &nokkuv1.UpdateTargetResponse{}, nil
}

func (s *targetService) RenameTarget(
	ctx context.Context,
	req *nokkuv1.RenameTargetRequest,
) (*nokkuv1.RenameTargetResponse, error) {
	result, err := s.cfg.Conn.Tenant().UpdateTarget(ctx, &db.UpdateTargetParams{
		TargetID: req.GetId(), Name: req.Name,
	})
	if err != nil {
		return nil, err
	}
	audit.Set(ctx, "name", result.Name)
	return &nokkuv1.RenameTargetResponse{}, nil
}

func (s *targetService) SetTargetEndpoints(
	ctx context.Context,
	req *nokkuv1.SetTargetEndpointsRequest,
) (*nokkuv1.SetTargetEndpointsResponse, error) {
	result, err := s.cfg.Conn.Tenant().UpdateTarget(ctx, &db.UpdateTargetParams{
		TargetID: req.GetId(), Endpoints: maskedList(true, req.GetEndpoints()),
	})
	if err != nil {
		return nil, err
	}
	audit.Set(ctx, "name", result.Name)
	audit.Set(ctx, "endpoints", result.Endpoints)
	return &nokkuv1.SetTargetEndpointsResponse{}, nil
}

func (s *targetService) DeleteTarget(
	ctx context.Context,
	req *nokkuv1.DeleteTargetRequest,
) (*nokkuv1.DeleteTargetResponse, error) {
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
		params := &db.ListTargetsParams{
			Query:          req.Query,
			Accounts:       req.GetAccounts(),
			Tags:           req.GetTags(),
			Ids:            req.GetIds(),
			Status:         targetStatuses[req.GetStatus()],
			Connected:      connected,
			MissedRollover: req.GetMissedRollover(),
			Limit:          req.Limit,
			Offset:         req.Offset,
		}
		rows, err := q.ListTargets(ctx, params)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			if req.GetOffset() == 0 {
				return nil
			}
			// A page past the end has no row to carry the total, the first row does.
			params.Limit, params.Offset = new(int32(1)), nil
			first, err := q.ListTargets(ctx, params)
			if err == nil && len(first) > 0 {
				count = first[0].TotalCount
			}
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
	caller, _ := actor.PrincipalFromContext(ctx)
	// A cookie would move a server without the fresh sign-in.
	if caller.Kind == actor.KindUser {
		return nil, connect.NewError(connect.CodePermissionDenied, "do this with nk")
	}
	if err := validateHostPublicKey(req.GetHostPublicKey()); err != nil {
		return nil, err
	}

	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		// Locked, or two reports that both saw no pin would both pin.
		target, err := q.LockTarget(ctx, req.GetTargetId())
		if err != nil {
			return err
		}
		if hasDaemon, err := q.HasDaemon(ctx, target.ID); err != nil {
			return err
		} else if hasDaemon {
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
			HostPublicKey: strings.TrimSpace(req.GetHostPublicKey()),
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
		target, err := q.GetTarget(ctx, req.GetTargetId())
		if err != nil {
			return err
		}
		audit.Set(ctx, "name", target.Name)
		if hasDaemon, err := q.HasDaemon(ctx, target.ID); err != nil {
			return err
		} else if hasDaemon {
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

		daemonRows, err := q.GetDaemonsByIDs(ctx, targetIDs)
		if err != nil {
			return err
		}
		daemons := make(map[string]*nokkuv1.Daemon, len(daemonRows))
		for _, d := range daemonRows {
			daemons[d.Daemon.TargetID] = &nokkuv1.Daemon{
				Id:     &d.Daemon.TargetID,
				Name:   &d.Name,
				Online: new(s.cfg.Pool.IsConnected(d.Daemon.TargetID)),
				// Only whether it records, so people know before they log in.
				Config: &nokkuv1.DaemonConfig{
					RecordSessions: new(db.ResolveDaemonConfig(d.Daemon.Config).GetRecordSessions()),
				},
			}
		}

		for _, r := range rows {
			target := r.ToProto()
			target.Accounts = accounts[r.ID]
			target.Daemon = daemons[r.ID]
			res.Targets = append(res.Targets, &nokkuv1.TargetAccess{Target: target})
		}
		setLogins(res.GetTargets(), uRows)
		slices.SortFunc(res.GetTargets(), func(a, b *nokkuv1.TargetAccess) int {
			return strings.Compare(a.GetTarget().GetName(), b.GetTarget().GetName())
		})

		ca, err := q.GetWorkspaceCA(ctx)
		if err != nil {
			return err
		}
		res.CertificateAuthority = ca.ToProto()
		return nil
	}); err != nil {
		return nil, err
	}
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

// setLogins also says why the logins let nobody in today.
func setLogins(targets []*nokkuv1.TargetAccess, rows []*db.ListSubjectUsernamesForTargetsRow) {
	byID := make(map[string]*nokkuv1.TargetAccess, len(targets))
	for _, t := range targets {
		byID[t.GetTarget().GetId()] = t
	}
	for _, r := range rows {
		target := byID[r.TargetID]
		if target == nil {
			continue
		}
		login := &nokkuv1.TargetAccess_Login{Username: &r.Username}
		if until := r.Until(); until != nil {
			login.ExpiresAt = timestamppb.New(*until)
		}
		target.Logins = append(target.Logins, login)
		switch {
		case !r.UserOk:
			target.Blocked = nokkuv1.AccessBlock_ACCESS_BLOCK_USER_INACTIVE.Enum()
		case !r.DaemonOk:
			target.Blocked = nokkuv1.AccessBlock_ACCESS_BLOCK_DAEMON_NOT_APPROVED.Enum()
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

func validateHostPublicKey(key string) error {
	if key == "" {
		return nil
	}
	if _, err := ssh.ParsePublicKey(key); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, "invalid host public key")
	}
	return nil
}
