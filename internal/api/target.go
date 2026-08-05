package api

import (
	"context"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
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
	meta.SetAuditWorkspaceID(ctx, req.GetWorkspaceId())

	if err := s.cfg.Entitlements.Check(
		ctx,
		req.GetWorkspaceId(),
		entitlement.ResourceTargets,
	); err != nil {
		return nil, err
	}

	var result *db.Target
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.CreateTarget(ctx, &db.CreateTargetParams{
			WorkspaceID: req.GetWorkspaceId(),
			Name:        req.GetName(),
			Description: req.Description,
			CaID:        req.CaId,
			Endpoints:   req.GetEndpoints(),
			Tags:        req.GetTags(),
		})
		if err != nil {
			return err
		}

		// Add a default root principal to the target
		return q.SyncPrincipals(ctx, &db.SyncPrincipalsParams{
			TargetID:  result.ID,
			Usernames: []string{"root"},
		})
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.CreateTargetResponse{
		Target: result.ToProto(),
	}, nil
}

func (s *TargetService) UpdateTarget(
	ctx context.Context,
	req *nokkuv1.UpdateTargetRequest,
) (*nokkuv1.UpdateTargetResponse, error) {
	var result *db.Target
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.UpdateTarget(ctx, &db.UpdateTargetParams{
			TargetID:    req.GetId(),
			Name:        req.Name,
			Description: req.Description,
			Endpoints:   req.GetEndpoints(),
			CaID:        req.CaId,
			Tags:        req.GetTags(),
		})
		if err != nil {
			return err
		}
		meta.SetAuditWorkspaceID(ctx, result.WorkspaceID)
		return nil
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
		result, err := q.DeleteTarget(ctx, req.GetId())
		meta.SetAuditWorkspaceID(ctx, result.WorkspaceID)
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
		Targets: db.ListTargetsToProto(targets),
		Total:   &count,
	}, nil
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
			principalsByTarget[p.TargetID] = append(principalsByTarget[p.TargetID], p.ToProto())
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
				cas = append(cas, &nokkuv1.CertificateAuthority{
					Id:             &ca.ID,
					WorkspaceId:    &ca.WorkspaceID,
					Name:           &ca.Name,
					PublicKey:      &ca.PublicKey,
					IsDefault:      &ca.IsDefault,
					AuthorityType:  &ca.AuthorityType,
					Certificate:    &ca.Certificate,
					UserDefaultTtl: db.SafeDuration(&ca.UserDefaultTtl),
					UserMaxTtl:     db.SafeDuration(&ca.UserMaxTtl),
				})
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
