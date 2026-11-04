package api

import (
	"cmp"
	"context"
	"slices"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/db"
)

const (
	// matrixColumns are the biggest tags a matrix shows when the caller picks none.
	matrixColumns = 12
	matrixRows    = 50
)

func (s *targetService) GetAccessMatrix(
	ctx context.Context,
	req *nokkuv1.GetAccessMatrixRequest,
) (*nokkuv1.GetAccessMatrixResponse, error) {
	var kind *string
	if req.GetKind() != nokkuv1.SubjectKind_SUBJECT_KIND_UNSPECIFIED {
		name, ok := subjectKind(req.GetKind())
		if !ok {
			return nil, errInvalidInput
		}
		kind = &name
	}

	res := &nokkuv1.GetAccessMatrixResponse{}
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		tags, err := q.CountTargetsByTag(ctx)
		if err != nil {
			return err
		}
		slices.SortFunc(tags, func(a, b *db.CountTargetsByTagRow) int {
			return cmp.Or(cmp.Compare(b.Total, a.Total), strings.Compare(a.Tag, b.Tag))
		})
		totals := make(map[string]int32, len(tags))
		for _, t := range tags {
			totals[t.Tag] = t.Total
			res.Tags = append(res.Tags, &nokkuv1.AccessGraphTag{Tag: &t.Tag, Total: &t.Total})
		}
		columns := req.GetTags()
		if len(columns) == 0 {
			for _, t := range tags[:min(len(tags), matrixColumns)] {
				columns = append(columns, t.Tag)
			}
		}
		for _, c := range columns {
			res.Columns = append(res.Columns, &nokkuv1.AccessGraphTag{Tag: new(c), Total: new(totals[c])})
		}

		rows, err := q.ListAccessMatrixRows(ctx, &db.ListAccessMatrixRowsParams{
			Kind:   kind,
			Query:  req.Query,
			Limit:  cmp.Or(req.GetLimit(), matrixRows),
			Offset: req.GetOffset(),
		})
		if err != nil || len(rows) == 0 {
			return err
		}
		res.Total = &rows[0].Total

		ids := make([]string, 0, len(rows))
		byID := make(map[string]*nokkuv1.AccessMatrixRow, len(rows))
		for _, r := range rows {
			row := &nokkuv1.AccessMatrixRow{
				SubjectId: &r.SubjectID,
				Kind:      new(subjectKinds[r.SubjectKind]),
				Name:      &r.Name,
				Targets:   &r.Targets,
			}
			switch r.SubjectKind {
			case db.SubjectKindUser:
				row.Email = &r.Email
			case db.SubjectKindTeam:
				row.MemberCount = &r.MemberCount
			}
			ids = append(ids, r.SubjectID)
			byID[r.SubjectID] = row
			res.Rows = append(res.Rows, row)
		}

		cells, err := q.ListAccessMatrixCells(ctx, &db.ListAccessMatrixCellsParams{SubjectIds: ids, Tags: columns})
		for _, c := range cells {
			byID[c.SubjectID].Cells = append(byID[c.SubjectID].Cells, matrixCell(c))
		}
		return err
	}); err != nil {
		return nil, err
	}
	return res, nil
}

func matrixCell(c *db.ListAccessMatrixCellsRow) *nokkuv1.AccessMatrixCell {
	cell := &nokkuv1.AccessMatrixCell{
		Tag:       &c.Tag,
		Targets:   &c.Targets,
		Usernames: c.Usernames,
	}
	if !c.ForGood {
		cell.ExpiresAt = timestamppb.New(c.ExpiresAt)
	}
	if c.Used {
		cell.LastUsedAt = timestamppb.New(c.LastUsedAt)
	}
	return cell
}
