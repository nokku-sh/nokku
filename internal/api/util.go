package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/config"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
)

type UtilService struct {
	cfg *config.Config
}

func NewUtilService(cfg *config.Config) *UtilService {
	return &UtilService{cfg: cfg}
}

func (s *UtilService) GetVersion(
	_ context.Context,
	_ *nokkuv1.GetVersionRequest,
) (*nokkuv1.GetVersionResponse, error) {
	return &nokkuv1.GetVersionResponse{Version: &buildinfo.Version}, nil
}

func (s *UtilService) ListAuditLogs(
	ctx context.Context,
	req *nokkuv1.ListAuditLogsRequest,
) (*nokkuv1.ListAuditLogsResponse, error) {
	actor := meta.ActorFromContext(ctx)
	var workspaceID string

	// Check if user is workspace member
	if req.GetWorkspaceId() != "" {
		workspaceID = req.GetWorkspaceId()
	} else {
		// Otherwise filter by current user if not filtering by workspace
		req.ActorIds = []string{actor.ID}
	}
	if workspaceID == "" && req.ActorIds == nil {
		return nil, NewError(connect.CodeInvalidArgument, "actor is required")
	}

	query := audit.QueryOptions{
		WorkspaceID: workspaceID,
		ActorIDs:    req.GetActorIds(),
		Actions:     req.GetActions(),
		Limit:       req.GetLimit(),
		Offset:      req.GetOffset(),
	}
	if t := req.GetStartDate(); t != nil {
		query.StartDate = t.AsTime()
	}
	if t := req.GetEndDate(); t != nil {
		query.EndDate = t.AsTime()
	}
	// Default to last 14 days if no dates provided
	if req.GetStartDate() == nil && req.GetEndDate() == nil {
		query.EndDate = time.Now()
		query.StartDate = query.EndDate.AddDate(0, 0, -14)
	}

	events, err := s.cfg.Audit.List(ctx, query)
	if err != nil {
		slog.Error("failed to list audit logs", "error", err)
		return nil, ErrInternal
	}

	count, err := s.cfg.Audit.Count(ctx, query)
	if err != nil {
		slog.Error("failed to count audit logs", "error", err)
		return nil, ErrInternal
	}

	return &nokkuv1.ListAuditLogsResponse{
		Logs:  audit.EventsToProto(events),
		Total: &count,
	}, nil
}

func (s *UtilService) ExportAuditLogs(
	ctx context.Context,
	req *nokkuv1.ExportAuditLogsRequest,
) (*nokkuv1.ExportAuditLogsResponse, error) {
	actor := meta.ActorFromContext(ctx)
	workspaceID := req.GetWorkspaceId()

	query := audit.QueryOptions{WorkspaceID: req.GetWorkspaceId()}
	if req.GetStartDate() != nil {
		query.StartDate = req.GetStartDate().AsTime()
	}
	if req.GetEndDate() != nil {
		query.EndDate = req.GetEndDate().AsTime()
	}
	// Default to last 14 days if no dates provided
	if req.GetStartDate() == nil && req.GetEndDate() == nil {
		query.EndDate = time.Now()
		query.StartDate = query.EndDate.AddDate(0, 0, -14)
	}

	// Filter by current user if not filtering by workspace
	if workspaceID == "" {
		query.ActorIDs = []string{actor.ID}
	}

	data, err := s.cfg.Audit.Export(ctx, query, req.GetFormat())
	if err != nil {
		return nil, ErrInternal
	}

	var ext string
	switch req.GetFormat() {
	case nokkuv1.ExportAuditLogsRequest_FORMAT_JSON:
		ext = "json"
	case nokkuv1.ExportAuditLogsRequest_FORMAT_CSV:
		ext = "csv"
	case nokkuv1.ExportAuditLogsRequest_FORMAT_UNSPECIFIED:
		ext = "json"
	}
	filename := fmt.Sprintf("audit-logs-%s.%s.gz", time.Now().Format("2006-01-02"), ext)
	contentType := "application/gzip"

	return &nokkuv1.ExportAuditLogsResponse{
		Data:        data,
		Filename:    &filename,
		ContentType: &contentType,
	}, nil
}
