package api

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/namegen"
	"github.com/nokku-sh/nokku/internal/ssh"
)

type TargetService struct {
	cfg *config.Config
}

func NewTargetService(cfg *config.Config) *TargetService {
	return &TargetService{cfg: cfg}
}

func (s *TargetService) GetTarget(
	ctx context.Context,
	req *nokkuv1.GetTargetRequest,
) (*nokkuv1.GetTargetResponse, error) {
	var target *db.Target
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		target, err = q.GetTarget(ctx, req.GetId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if target == nil {
		return nil, ErrNotFound
	}

	return &nokkuv1.GetTargetResponse{
		Target: target.ToProto(),
	}, nil
}

func (s *TargetService) CreateTarget(
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
			return nil, DBError(err)
		}
		return created, nil
	}

	// No name from the caller, which is what a manual sync sends: generate a
	// friendly one. Names are unique per workspace, so a collision retries
	// with a numeric suffix, the way daemon enrollment does.
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
			return nil, DBError(err)
		}
	}
}

// insertTarget creates the target and its default root principal in one
// transaction. The name must already be resolved. The error is returned
// unmapped so the caller can tell a name collision from a real failure.
func (s *TargetService) insertTarget(
	ctx context.Context,
	req *nokkuv1.CreateTargetRequest,
	name string,
) (*nokkuv1.CreateTargetResponse, error) {
	var result *db.Target
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.CreateTarget(ctx, &db.CreateTargetParams{
			WorkspaceID:   req.GetWorkspaceId(),
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

		// Add a default root principal to the target
		return q.SetPrincipals(ctx, &db.SetPrincipalsParams{
			TargetID:  result.ID,
			Usernames: []string{"root"},
		})
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.CreateTargetResponse{
		Target: result.ToProto(),
	}, nil
}

func (s *TargetService) UpdateTarget(
	ctx context.Context,
	req *nokkuv1.UpdateTargetRequest,
) (*nokkuv1.UpdateTargetResponse, error) {
	if err := validateHostPublicKey(req.GetHostPublicKey()); err != nil {
		return nil, err
	}
	var result *db.Target
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.UpdateTarget(ctx, &db.UpdateTargetParams{
			TargetID:      req.GetId(),
			Name:          req.Name,
			Description:   req.Description,
			Endpoints:     req.GetEndpoints(),
			CaID:          req.CaId,
			Tags:          req.GetTags(),
			HostPublicKey: trimmed(req.HostPublicKey),
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.UpdateTargetResponse{
		Target: result.ToProto(),
	}, nil
}

func (s *TargetService) DeleteTarget(
	ctx context.Context,
	req *nokkuv1.DeleteTargetRequest,
) (*nokkuv1.DeleteTargetResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		_, err := q.DeleteTarget(ctx, req.GetId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.DeleteTargetResponse{}, nil
}

func (s *TargetService) ListTargets(
	ctx context.Context,
	req *nokkuv1.ListTargetsRequest,
) (*nokkuv1.ListTargetsResponse, error) {
	var targets []*db.ListTargetsRow
	count := int32(0)
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		targets, err = q.ListTargets(ctx, &db.ListTargetsParams{
			WorkspaceID: req.GetWorkspaceId(),
			Query:       req.Query,
			DaemonID:    req.DaemonId,
			CaID:        req.CaId,
			Principals:  req.GetPrincipals(),
			Tags:        req.GetTags(),
			Limit:       req.Limit,
			Offset:      req.Offset,
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if len(targets) > 0 {
		count = targets[0].TotalCount
	}

	return &nokkuv1.ListTargetsResponse{
		Targets: db.TargetsToProto(targets),
		Total:   &count,
	}, nil
}

// GetTargetPrincipals returns the per-account subject list for one target,
// with teams expanded. It is what a daemonless host needs: the operator writes
// it into AuthorizedPrincipalsFile, so the host's own sshd enforces the same
// grant predicate the daemon would.
func (s *TargetService) GetTargetPrincipals(
	ctx context.Context,
	req *nokkuv1.GetTargetPrincipalsRequest,
) (*nokkuv1.GetTargetPrincipalsResponse, error) {
	var rows []*db.ListPrincipalsForTargetRow
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		rows, err = q.ListPrincipalsForTarget(ctx, req.GetTargetId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	principals := make([]*nokkuv1.PrincipalUsers, 0, len(rows))
	for _, r := range rows {
		username := r.Username
		principals = append(principals, &nokkuv1.PrincipalUsers{
			Username: &username,
			Ids:      r.Ids,
		})
	}
	return &nokkuv1.GetTargetPrincipalsResponse{Principals: principals}, nil
}

// SyncTargetUsers reports a target's local accounts, host key, and endpoints.
// Daemonless targets use it: the operator runs the report from their own
// machine over SSH. The account list only creates anchors and never deletes,
// so a failed report cannot lock anyone out.
func (s *TargetService) SyncTargetUsers(
	ctx context.Context,
	req *nokkuv1.SyncTargetUsersRequest,
) (*nokkuv1.SyncTargetUsersResponse, error) {
	if err := validateHostPublicKey(req.GetHostPublicKey()); err != nil {
		return nil, err
	}

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		if err := q.InsertTargetPrincipals(ctx, &db.InsertTargetPrincipalsParams{
			TargetID:  req.GetTargetId(),
			Usernames: req.GetUsernames(),
		}); err != nil {
			return err
		}

		// Only the fields the report carries: the update COALESCEs, so nil
		// leaves the stored value alone.
		params := &db.UpdateTargetParams{TargetID: req.GetTargetId()}
		if len(req.GetEndpoints()) > 0 {
			params.Endpoints = req.GetEndpoints()
		}
		if req.GetHostPublicKey() != "" {
			params.HostPublicKey = trimmed(req.HostPublicKey)
		}
		if params.Endpoints == nil && params.HostPublicKey == nil {
			return nil
		}
		_, err := q.UpdateTarget(ctx, params)
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	s.cfg.Pool.NotifyChange(req.GetWorkspaceId())
	return &nokkuv1.SyncTargetUsersResponse{}, nil
}

func (s *TargetService) GetSubjectAccess(
	ctx context.Context,
	req *nokkuv1.GetSubjectAccessRequest,
) (*nokkuv1.GetSubjectAccessResponse, error) {
	var targets []*nokkuv1.Target
	var daemons []*nokkuv1.Daemon
	var cas []*nokkuv1.CertificateAuthority

	uniqueDaemonIDs := make(map[string]struct{})
	uniqueCAIDs := make(map[string]struct{})

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
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

		principalsByTarget := make(map[string][]*nokkuv1.Principal)
		pRows, err := q.GetPrincipalsByTargetIDs(ctx, targetIDs)
		if err != nil {
			return err
		}
		for _, p := range pRows {
			targetID := p.Principal.TargetID
			principalsByTarget[targetID] = append(principalsByTarget[targetID], p.ToProto())
		}

		for _, r := range rows {
			target := r.ToProto()
			target.Principals = principalsByTarget[r.ID]
			targets = append(targets, target)
		}

		if len(uniqueDaemonIDs) > 0 {
			daemonIDsArg := make([]string, 0, len(uniqueDaemonIDs))
			for id := range uniqueDaemonIDs {
				daemonIDsArg = append(daemonIDsArg, id)
			}

			daemonRows, err := q.GetDaemonsByIDs(ctx, daemonIDsArg)
			if err != nil {
				return err
			}
			for _, d := range daemonRows {
				daemons = append(daemons, &nokkuv1.Daemon{
					Id:     &d.ID,
					Name:   &d.Name,
					Online: &d.Online,
				})
			}
		}

		if len(uniqueCAIDs) > 0 {
			caIDsArg := make([]string, 0, len(uniqueCAIDs))
			for id := range uniqueCAIDs {
				caIDsArg = append(caIDsArg, id)
			}

			caRows, err := q.GetCAsByIDs(ctx, caIDsArg)
			if err != nil {
				return err
			}
			for _, ca := range caRows {
				cas = append(cas, ca.ToProto())
			}
		}
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.GetSubjectAccessResponse{
		Targets:                targets,
		CertificateAuthorities: cas,
		Daemons:                daemons,
	}, nil
}

func (s *TargetService) GetMyAccess(
	ctx context.Context,
	_ *nokkuv1.GetMyAccessRequest,
) (*nokkuv1.GetMyAccessResponse, error) {
	p, ok := iam.PrincipalFromContext(ctx)
	if !ok || p.ID == "" {
		return nil, NewError(connect.CodeUnauthenticated, "not authenticated")
	}
	//nolint:exhaustive // daemons (and any future kind) are intentionally excluded
	switch p.Kind {
	case iam.KindUser, iam.KindCLI, iam.KindWebDevice, iam.KindServiceAccount:
	default:
		return nil, NewError(
			connect.CodePermissionDenied,
			"unsupported principal kind; daemons sync through SyncDaemon",
		)
	}

	resp := &nokkuv1.GetMyAccessResponse{}
	err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		// The workspace set is the source of truth for "what can this actor
		// see at all"; every query below filters against it.
		wsIDs, err := q.GetActorWorkspaceIDs(ctx, p.ID)
		if err != nil {
			return err
		}
		if len(wsIDs) == 0 {
			return nil
		}

		//nolint:exhaustive // daemon was rejected above; the remaining kinds are user-like or service account
		switch p.Kind {
		case iam.KindUser, iam.KindCLI, iam.KindWebDevice:
			u, err := s.cfg.IAM.GetUser(ctx)
			if err != nil {
				return err
			}
			resp.Subject = &nokkuv1.GetMyAccessResponse_User{User: u.ToProto()}
		case iam.KindServiceAccount:
			sa, err := q.GetServiceAccount(ctx, p.ID)
			if err != nil {
				return err
			}
			resp.Subject = &nokkuv1.GetMyAccessResponse_ServiceAccount{ServiceAccount: sa.ToProto()}
		}

		wsRows, err := q.GetWorkspacesByIDs(ctx, wsIDs)
		if err != nil {
			return err
		}
		wsNames := make(map[string]string, len(wsRows))
		for _, w := range wsRows {
			wsNames[w.ID] = w.Name
		}

		rows, err := q.GetSubjectTargetsByWorkspaces(ctx, &db.GetSubjectTargetsByWorkspacesParams{
			WorkspaceIds: wsIDs,
			SubjectID:    p.ID,
		})
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}

		targetIDs := make([]string, 0, len(rows))
		caIDs := make(map[string]struct{})
		targetsByWS := make(map[string][]*nokkuv1.Target, len(wsRows))
		for _, r := range rows {
			targetIDs = append(targetIDs, r.ID)
			if r.CaID != nil {
				caIDs[*r.CaID] = struct{}{}
			}
			target := r.ToProto()
			targetsByWS[r.WorkspaceID] = append(targetsByWS[r.WorkspaceID], target)
		}

		// Resolve the grant predicate for this one subject: the CLI needs the
		// local accounts it may use, not the target's assignment graph.
		usernamesByTarget := make(map[string][]string)
		uRows, err := q.ListSubjectUsernamesForTargets(
			ctx,
			&db.ListSubjectUsernamesForTargetsParams{
				TargetIds: targetIDs,
				SubjectID: p.ID,
			},
		)
		if err != nil {
			return err
		}
		for _, u := range uRows {
			usernamesByTarget[u.TargetID] = append(
				usernamesByTarget[u.TargetID], u.Username,
			)
		}
		for wsID, targets := range targetsByWS {
			for _, t := range targets {
				t.Usernames = usernamesByTarget[t.GetId()]
			}
			// Row order from the query is (workspace_id, name); keep it so
			// consumers get a deterministic snapshot.
			slices.SortStableFunc(targets, func(a, b *nokkuv1.Target) int {
				return strings.Compare(a.GetName(), b.GetName())
			})
			targetsByWS[wsID] = targets
		}

		caArgs := make([]string, 0, len(caIDs))
		for id := range caIDs {
			caArgs = append(caArgs, id)
		}
		casByWS := make(map[string][]*nokkuv1.CertificateAuthority)
		if len(caArgs) > 0 {
			caRows, err := q.GetCAsByIDs(ctx, caArgs)
			if err != nil {
				return err
			}
			for _, ca := range caRows {
				// Only SSH authorities belong in an access snapshot; X.509
				// CAs are listed separately and must not leak into SSH
				// trust stores.
				if ca.AuthorityType != nokkuv1.AuthorityType_AUTHORITY_TYPE_SSH {
					continue
				}
				casByWS[ca.WorkspaceID] = append(casByWS[ca.WorkspaceID], ca.ToProto())
			}
		}

		for _, w := range wsRows {
			resp.Workspaces = append(resp.Workspaces, &nokkuv1.WorkspaceAccess{
				WorkspaceId:            &w.ID,
				WorkspaceName:          &w.Name,
				Targets:                targetsByWS[w.ID],
				CertificateAuthorities: casByWS[w.ID],
			})
		}
		return nil
	})
	if err != nil {
		return nil, DBError(err)
	}
	return resp, nil
}

func (s *TargetService) GetTargetFilters(
	ctx context.Context,
	req *nokkuv1.GetTargetFiltersRequest,
) (*nokkuv1.GetTargetFiltersResponse, error) {
	var tags []string
	var principals []string

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		tags, err = q.GetWorkspaceTags(ctx, req.GetWorkspaceId())
		if err != nil {
			return err
		}

		principals, err = q.GetWorkspacePrincipals(ctx, req.GetWorkspaceId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.GetTargetFiltersResponse{
		Tags:       tags,
		Principals: principals,
	}, nil
}

// validateHostPublicKey rejects malformed host keys early so a typo in a
// provisioning script never pins an unusable identity.
func validateHostPublicKey(key string) error {
	if key == "" {
		return nil
	}
	if _, err := ssh.ParsePublicKey(key); err != nil {
		return NewError(connect.CodeInvalidArgument, "invalid host public key")
	}
	return nil
}

// trimmed normalizes an optional proto string: nil stays nil, empty becomes
// nil so COALESCE keeps the stored value.
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
