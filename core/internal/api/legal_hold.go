package api

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect/v2"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// maxLegalHolds is far above a real need. Each hold is checked on every retention delete.
const maxLegalHolds = 20

type legalHoldService struct {
	cfg *config.Config
}

func (s *legalHoldService) ListLegalHolds(
	ctx context.Context,
	_ *nokkuv1.ListLegalHoldsRequest,
) (*nokkuv1.ListLegalHoldsResponse, error) {
	holds, err := s.cfg.Conn.Tenant().ListLegalHolds(ctx)
	if err != nil {
		return nil, err
	}
	return &nokkuv1.ListLegalHoldsResponse{Holds: db.LegalHoldsToProto(holds)}, nil
}

func (s *legalHoldService) CreateLegalHold(
	ctx context.Context,
	req *nokkuv1.CreateLegalHoldRequest,
) (*nokkuv1.CreateLegalHoldResponse, error) {
	var endsAt *time.Time
	if req.GetEndsAt() != nil {
		endsAt = new(req.GetEndsAt().AsTime())
	}
	var createdBy *string
	if id := actor.UserIDFromContext(ctx); id != "" {
		createdBy = &id
	}
	var hold *db.LegalHold
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		n, err := q.CountLegalHolds(ctx)
		if err != nil {
			return err
		}
		if n >= maxLegalHolds {
			return newError(connect.CodeResourceExhausted,
				fmt.Sprintf("a workspace holds at most %d ranges, release one first", maxLegalHolds))
		}
		hold, err = q.CreateLegalHold(ctx, &db.CreateLegalHoldParams{
			Reason:    req.GetReason(),
			StartsAt:  req.GetStartsAt().AsTime(),
			EndsAt:    endsAt,
			CreatedBy: createdBy,
		})
		return err
	}); err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, hold.ID)
	audit.Set(ctx, "reason", hold.Reason)
	return &nokkuv1.CreateLegalHoldResponse{Hold: hold.ToProto()}, nil
}

func (s *legalHoldService) DeleteLegalHold(
	ctx context.Context,
	req *nokkuv1.DeleteLegalHoldRequest,
) (*nokkuv1.DeleteLegalHoldResponse, error) {
	hold, err := s.cfg.Conn.Tenant().DeleteLegalHold(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	// The row is gone, the audit log keeps what it held.
	audit.Set(ctx, "reason", hold.Reason)
	audit.Set(ctx, "starts_at", hold.StartsAt)
	if hold.EndsAt != nil {
		audit.Set(ctx, "ends_at", *hold.EndsAt)
	}
	return &nokkuv1.DeleteLegalHoldResponse{}, nil
}
