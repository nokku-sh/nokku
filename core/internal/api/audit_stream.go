package api

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// maxAuditStreams covers a SIEM, an archive and one on trial.
const maxAuditStreams = 3

type auditStreamService struct {
	cfg *config.Config
}

func (s *auditStreamService) ListAuditStreams(
	ctx context.Context,
	_ *nokkuv1.ListAuditStreamsRequest,
) (*nokkuv1.ListAuditStreamsResponse, error) {
	rows, err := s.cfg.Conn.Tenant().ListAuditStreams(ctx)
	if err != nil {
		return nil, err
	}
	streams := make([]*nokkuv1.AuditStream, len(rows))
	for i, r := range rows {
		streams[i] = r.ToProto()
	}
	return &nokkuv1.ListAuditStreamsResponse{Streams: streams}, nil
}

func (s *auditStreamService) CreateAuditStream(
	ctx context.Context,
	req *nokkuv1.CreateAuditStreamRequest,
) (*nokkuv1.CreateAuditStreamResponse, error) {
	kind := db.AuditStreamKind(req.GetKind())
	var row *db.CreateAuditStreamRow
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		n, err := q.CountAuditStreams(ctx)
		if err != nil {
			return err
		}
		if n >= maxAuditStreams {
			return newError(connect.CodeResourceExhausted,
				fmt.Sprintf("a workspace has at most %d streams", maxAuditStreams))
		}
		row, err = q.CreateAuditStream(ctx, &db.CreateAuditStreamParams{
			Kind:   kind,
			URL:    req.GetUrl(),
			Secret: crypto.EncryptedBytes(req.GetSecret()),
		})
		return err
	}); err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, row.ID)
	audit.Set(ctx, "kind", kind)
	audit.Set(ctx, "url", req.GetUrl())
	return &nokkuv1.CreateAuditStreamResponse{Stream: (*db.ListAuditStreamsRow)(row).ToProto()}, nil
}

func (s *auditStreamService) UpdateAuditStream(
	ctx context.Context,
	req *nokkuv1.UpdateAuditStreamRequest,
) (*nokkuv1.UpdateAuditStreamResponse, error) {
	row, err := s.cfg.Conn.Tenant().UpdateAuditStream(ctx, &db.UpdateAuditStreamParams{
		ID:      req.GetId(),
		URL:     req.Url,
		Secret:  crypto.EncryptedBytes(req.GetSecret()),
		Enabled: req.Enabled,
	})
	if err != nil {
		return nil, err
	}
	if req.Url != nil {
		audit.Set(ctx, "url", req.GetUrl())
	}
	if req.Enabled != nil {
		audit.Set(ctx, "enabled", req.GetEnabled())
	}
	audit.Set(ctx, "secret_changed", req.Secret != nil)
	return &nokkuv1.UpdateAuditStreamResponse{Stream: (*db.ListAuditStreamsRow)(row).ToProto()}, nil
}

func (s *auditStreamService) DeleteAuditStream(
	ctx context.Context,
	req *nokkuv1.DeleteAuditStreamRequest,
) (*nokkuv1.DeleteAuditStreamResponse, error) {
	deleted, err := s.cfg.Conn.Tenant().DeleteAuditStream(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if deleted == 0 {
		return nil, newError(connect.CodeNotFound, "no such stream")
	}
	return &nokkuv1.DeleteAuditStreamResponse{}, nil
}

func (s *auditStreamService) TestAuditStream(
	ctx context.Context,
	req *nokkuv1.TestAuditStreamRequest,
) (*nokkuv1.TestAuditStreamResponse, error) {
	st, err := s.cfg.Conn.Tenant().GetAuditStream(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if err := s.cfg.Audit.TestStream(ctx, st); err != nil {
		return nil, newError(connect.CodeFailedPrecondition, err.Error())
	}
	return &nokkuv1.TestAuditStreamResponse{}, nil
}
