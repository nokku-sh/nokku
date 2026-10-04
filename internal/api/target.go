package api

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/namegen"
	"github.com/nokku-sh/nokku/internal/ssh"
)

type targetService struct {
	cfg *config.Config
}

func newTargetService(cfg *config.Config) *targetService {
	return &targetService{cfg: cfg}
}

func (s *targetService) GetTarget(
	ctx context.Context,
	req *nokkuv1.GetTargetRequest,
) (*nokkuv1.GetTargetResponse, error) {
	var target *db.Target
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		target, err = q.GetTarget(ctx, req.GetId())
		return err
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.GetTargetResponse{
		Target: target.ToProto(),
	}, nil
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

		return q.InsertTargetPrincipals(ctx, &db.InsertTargetPrincipalsParams{
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

func (s *targetService) UpdateTarget(
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
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		_, err := q.DeleteTarget(ctx, req.GetId())
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
	var targets []*db.ListTargetsRow
	var count int32
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
		return nil, err
	}
	if len(targets) > 0 {
		count = targets[0].TotalCount
	}

	return &nokkuv1.ListTargetsResponse{
		Targets: db.TargetsToProto(targets),
		Total:   &count,
	}, nil
}

// GetTargetPrincipals feeds AuthorizedPrincipalsFile on daemonless hosts.
func (s *targetService) GetTargetPrincipals(
	ctx context.Context,
	req *nokkuv1.GetTargetPrincipalsRequest,
) (*nokkuv1.GetTargetPrincipalsResponse, error) {
	var rows []*db.ListPrincipalsForTargetRow
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		rows, err = q.ListPrincipalsForTarget(ctx, req.GetTargetId())
		return err
	}); err != nil {
		return nil, err
	}

	principals := make([]*nokkuv1.PrincipalUsers, 0, len(rows))
	for _, r := range rows {
		principals = append(principals, &nokkuv1.PrincipalUsers{
			Username: &r.Username,
			Ids:      r.Ids,
		})
	}
	return &nokkuv1.GetTargetPrincipalsResponse{Principals: principals}, nil
}

// SyncTargetUsers is the daemonless report. It never deletes accounts, so a
// failed report cannot lock anyone out.
func (s *targetService) SyncTargetUsers(
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

		if err := q.TouchTargetManualSync(ctx, req.GetTargetId()); err != nil {
			return err
		}

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
		return nil, err
	}

	return &nokkuv1.SyncTargetUsersResponse{}, nil
}

func (s *targetService) GetSubjectAccess(
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
			"unsupported principal kind; daemons sync through SyncDaemon",
		)
	}

	resp := &nokkuv1.GetMyAccessResponse{}
	err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		// Every query below filters against the actor's workspaces.
		wsIDs, err := q.GetActorWorkspaceIDs(ctx, p.ID)
		if err != nil {
			return err
		}
		if len(wsIDs) == 0 {
			return nil
		}

		//nolint:exhaustive // other kinds were rejected above
		switch p.Kind {
		case actor.KindUser, actor.KindCLI:
			u, err := s.cfg.IAM.GetUser(ctx)
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
			targetsByWS[r.WorkspaceID] = append(targetsByWS[r.WorkspaceID], r.ToProto())
		}

		// The CLI needs the accounts this subject may use, not the whole graph.
		usernamesByTarget := make(map[string][]string)
		uRows, err := q.ListSubjectUsernamesForTargets(
			ctx,
			&db.ListSubjectUsernamesForTargetsParams{
				TargetIds: targetIDs,
				SubjectID: &p.ID,
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
		for _, targets := range targetsByWS {
			for _, t := range targets {
				t.Usernames = usernamesByTarget[t.GetId()]
			}
			slices.SortFunc(targets, func(a, b *nokkuv1.Target) int {
				return strings.Compare(a.GetName(), b.GetName())
			})
		}

		casByWS := make(map[string][]*nokkuv1.CertificateAuthority)
		if len(caIDs) > 0 {
			caRows, err := q.GetCAsByIDs(ctx, slices.Collect(maps.Keys(caIDs)))
			if err != nil {
				return err
			}
			for _, ca := range caRows {
				// X.509 CAs must not leak into SSH trust stores.
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
		return nil, err
	}
	return resp, nil
}

func (s *targetService) GetTargetFilters(
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
		return nil, err
	}

	return &nokkuv1.GetTargetFiltersResponse{
		Tags:       tags,
		Principals: principals,
	}, nil
}

// GetAccessGraph backs the topology page. Everything is counted in one
// grouped query, so the response stays small whatever the workspace size.
func (s *targetService) GetAccessGraph(
	ctx context.Context,
	req *nokkuv1.GetAccessGraphRequest,
) (*nokkuv1.GetAccessGraphResponse, error) {
	filter := cmp.Or(req.GetFilter(), &nokkuv1.AccessGraphFilter{})
	resp := &nokkuv1.GetAccessGraphResponse{}

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
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

		// A user who only has access through teams holds nothing, but the
		// caller still needs their name.
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
	var rows []*db.ListAccessGraphTargetsRow
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		rows, err = q.ListAccessGraphTargets(ctx, &db.ListAccessGraphTargetsParams{
			Tag:       req.GetTag(),
			FilterTag: filter.Tag,
			SubjectID: filter.SubjectId,
			TargetID:  filter.TargetId,
			Username:  filter.Username,
			Limit:     req.Limit,
			Offset:    req.Offset,
		})
		return err
	}); err != nil {
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
