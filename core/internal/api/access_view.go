package api

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/access"
	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/db"
)

type accessViewService struct {
	cfg *app.Config
}

// GetAccessGraph counts in one grouped query, so the response stays small.
func (s *accessViewService) GetAccessGraph(
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
					SubjectId:   &r.SubjectID,
					Username:    &r.Username,
					TargetCount: &r.Targets,
				})
			case r.ByUsername && r.ByTag:
				resp.Reach = append(resp.Reach, &nokkuv1.AccessGraphReach{
					Username:    &r.Username,
					Tag:         &r.Tag,
					TargetCount: &r.Targets,
				})
			case r.BySubject:
				held[r.SubjectID] = r.Targets
			case r.ByUsername:
				resp.Accounts = append(resp.Accounts, &nokkuv1.AccessGraphAccount{
					Username:    &r.Username,
					TargetCount: &r.Targets,
				})
			case r.ByTag:
				matched[r.Tag] = r.Targets
			default:
				resp.TargetCount = &r.Targets
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
			resp.Subjects = append(resp.Subjects, &nokkuv1.AccessSubject{
				Id:          &sub.ID,
				Kind:        db.SubjectKinds[sub.Kind].Enum(),
				Name:        &sub.Name,
				Email:       &sub.Email,
				MemberCount: &sub.MemberCount,
				TargetCount: new(held[sub.ID]),
			})
		}

		tags, err := q.CountTargetsByTag(ctx)
		if err != nil {
			return err
		}
		for _, t := range tags {
			resp.Tags = append(resp.Tags, &nokkuv1.AccessTag{
				Tag:                &t.Tag,
				GrantedTargetCount: new(matched[t.Tag]),
				TargetCount:        &t.Total,
			})
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *accessViewService) ListAccessGraphTargets(
	ctx context.Context,
	req *nokkuv1.ListAccessGraphTargetsRequest,
) (*nokkuv1.ListAccessGraphTargetsResponse, error) {
	filter := cmp.Or(req.GetFilter(), &nokkuv1.AccessGraphFilter{})
	q := s.cfg.Conn.Tenant()
	params := &db.ListAccessGraphTargetsParams{
		Tag:       req.GetTag(),
		FilterTag: filter.Tag,
		SubjectID: filter.SubjectId,
		TargetID:  filter.TargetId,
		Username:  filter.Username,
		Limit:     req.Limit,
		Offset:    req.Offset,
	}
	rows, err := q.ListAccessGraphTargets(ctx, params)
	if err != nil {
		return nil, err
	}
	counted := rows
	if len(rows) == 0 && req.GetOffset() > 0 {
		// A page past the end has no row to carry the total, the first row does.
		params.Limit, params.Offset = new(int32(1)), nil
		if counted, err = q.ListAccessGraphTargets(ctx, params); err != nil {
			return nil, err
		}
	}
	var total int32
	if len(counted) > 0 {
		total = counted[0].TotalCount
	}

	targets := make([]*nokkuv1.AccessGraphTarget, 0, len(rows))
	for _, r := range rows {
		targets = append(targets, &nokkuv1.AccessGraphTarget{
			Id:      &r.ID,
			Name:    &r.Name,
			Matched: &r.Matched,
		})
	}
	return &nokkuv1.ListAccessGraphTargetsResponse{Targets: targets, Total: &total}, nil
}

func (s *accessViewService) ExportAccessReport(
	ctx context.Context,
	req *nokkuv1.ExportAccessReportRequest,
) (*nokkuv1.ExportAccessReportResponse, error) {
	rows, err := s.cfg.Conn.Tenant().ListAccessReport(ctx)
	if err != nil {
		return nil, err
	}
	data, err := access.Report(rows, req.GetFormat())
	if err != nil {
		return nil, err
	}

	ext, contentType := "json", "application/json"
	if req.GetFormat() == nokkuv1.ExportAuditLogsRequest_FORMAT_CSV {
		ext, contentType = "csv", "text/csv"
	}
	return &nokkuv1.ExportAccessReportResponse{
		Data:        data,
		Filename:    new(fmt.Sprintf("access-report-%s.%s", time.Now().Format(time.DateOnly), ext)),
		ContentType: new(contentType),
	}, nil
}
