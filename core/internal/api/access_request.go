package api

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/email"
)

type accessRequestService struct {
	cfg *config.Config
}

// maxDailyRequests keeps asking and cancelling from filling the table and the admins' inboxes.
const maxDailyRequests = 50

func (s *accessRequestService) ListRequestableAccounts(
	ctx context.Context,
	_ *nokkuv1.ListRequestableAccountsRequest,
) (*nokkuv1.ListRequestableAccountsResponse, error) {
	rows, err := s.cfg.Conn.Tenant().ListRequestableAccounts(ctx)
	if err != nil {
		return nil, err
	}
	targets := make([]*nokkuv1.RequestableTarget, len(rows))
	for i, r := range rows {
		targets[i] = &nokkuv1.RequestableTarget{Id: &r.ID, Name: &r.Name, Usernames: r.Usernames}
	}
	return &nokkuv1.ListRequestableAccountsResponse{Targets: targets}, nil
}

func (s *accessRequestService) CreateAccessRequest(
	ctx context.Context,
	req *nokkuv1.CreateAccessRequestRequest,
) (*nokkuv1.CreateAccessRequestResponse, error) {
	userID := actor.UserIDFromContext(ctx)
	if userID == "" {
		return nil, newError(connect.CodePermissionDenied, "only people can ask for access")
	}

	var id string
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		recent, err := q.CountRecentAccessRequests(ctx, userID)
		if err != nil {
			return err
		}
		if recent >= maxDailyRequests {
			return newError(connect.CodeResourceExhausted,
				fmt.Sprintf("you asked %d times today, try again tomorrow", maxDailyRequests))
		}
		// A target that is not requestable answers like one that does not exist.
		accountID, err := q.GetRequestableAccount(ctx, &db.GetRequestableAccountParams{
			Target:   req.GetTarget(),
			Username: req.GetUsername(),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return newError(connect.CodeNotFound, "there is no such account to ask for")
		}
		if err != nil {
			return err
		}
		id, err = q.CreateAccessRequest(ctx, &db.CreateAccessRequestParams{
			RequesterID: userID,
			AccountID:   accountID,
			Duration:    req.GetDuration().AsDuration(),
			Reason:      req.GetReason(),
		})
		if db.IsUniqueViolation(err) {
			return newError(connect.CodeAlreadyExists, "you already asked for this account, it waits for an answer")
		}
		return err
	}); err != nil {
		return nil, err
	}

	row, err := s.cfg.Conn.Tenant().GetAccessRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, id)
	audit.Set(ctx, "target", row.TargetName)
	audit.Set(ctx, "username", row.Username)
	audit.Set(ctx, "duration", row.Duration.String())
	audit.Set(ctx, "reason", row.Reason)
	if s.cfg.Email.HasSMTP() {
		go s.notifyApprovers(context.WithoutCancel(ctx), row)
	}
	return &nokkuv1.CreateAccessRequestResponse{Request: row.ToProto()}, nil
}

func (s *accessRequestService) GetAccessRequest(
	ctx context.Context,
	req *nokkuv1.GetAccessRequestRequest,
) (*nokkuv1.GetAccessRequestResponse, error) {
	row, err := s.cfg.Conn.Tenant().GetAccessRequest(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if callerRole(ctx) < nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN &&
		row.RequesterID != actor.UserIDFromContext(ctx) {
		return nil, newError(connect.CodeNotFound, "no such request")
	}
	return &nokkuv1.GetAccessRequestResponse{Request: row.ToProto()}, nil
}

func (s *accessRequestService) ListAccessRequests(
	ctx context.Context,
	req *nokkuv1.ListAccessRequestsRequest,
) (*nokkuv1.ListAccessRequestsResponse, error) {
	var requester, status *string
	if callerRole(ctx) < nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN {
		userID := actor.UserIDFromContext(ctx)
		// Only people ask, so a service account has no requests of its own.
		if userID == "" {
			return &nokkuv1.ListAccessRequestsResponse{Total: new(int32(0))}, nil
		}
		requester = &userID
	}
	if name := db.AccessRequestStatus(req.GetStatus()); name != "" {
		status = &name
	}

	rows, err := s.cfg.Conn.Tenant().ListAccessRequests(ctx, &db.ListAccessRequestsParams{
		Status:      status,
		RequesterID: requester,
		Limit:       req.Limit,
		Offset:      req.Offset,
	})
	if err != nil {
		return nil, err
	}
	var total int32
	requests := make([]*nokkuv1.AccessRequest, len(rows))
	for i, r := range rows {
		total = r.TotalCount
		requests[i] = r.AccessRequestDetail.ToProto()
	}
	return &nokkuv1.ListAccessRequestsResponse{Requests: requests, Total: &total}, nil
}

func (s *accessRequestService) ApproveAccessRequest(
	ctx context.Context,
	req *nokkuv1.ApproveAccessRequestRequest,
) (*nokkuv1.ApproveAccessRequestResponse, error) {
	row, err := s.decide(ctx, req.GetId(), nokkuv1.AccessRequestStatus_ACCESS_REQUEST_STATUS_APPROVED)
	if err != nil {
		return nil, err
	}
	return &nokkuv1.ApproveAccessRequestResponse{Request: row.ToProto()}, nil
}

func (s *accessRequestService) DenyAccessRequest(
	ctx context.Context,
	req *nokkuv1.DenyAccessRequestRequest,
) (*nokkuv1.DenyAccessRequestResponse, error) {
	row, err := s.decide(ctx, req.GetId(), nokkuv1.AccessRequestStatus_ACCESS_REQUEST_STATUS_DENIED)
	if err != nil {
		return nil, err
	}
	return &nokkuv1.DenyAccessRequestResponse{Request: row.ToProto()}, nil
}

// decide answers a pending request. An approval grants the account from now for the duration asked, and never
// shortens access the requester already has.
func (s *accessRequestService) decide(
	ctx context.Context,
	id string,
	status nokkuv1.AccessRequestStatus,
) (*db.AccessRequestDetail, error) {
	caller := actor.UserIDFromContext(ctx)
	if caller == "" {
		return nil, newError(connect.CodePermissionDenied, "only people can answer requests")
	}

	var row *db.AccessRequestDetail
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		_, err := q.DecideAccessRequest(ctx, &db.DecideAccessRequestParams{
			Status:    db.AccessRequestStatus(status),
			DecidedBy: caller,
			ID:        id,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return whyUndecided(ctx, q, id, caller)
		}
		if err != nil {
			return err
		}
		if row, err = q.GetAccessRequest(ctx, id); err != nil {
			return err
		}
		if until := row.GrantedUntil(); until != nil {
			return q.ExtendGrant(ctx, &db.ExtendGrantParams{
				AccountID: row.AccountID,
				UserID:    row.RequesterID,
				ExpiresAt: *until,
			})
		}
		return nil
	}); err != nil {
		return nil, err
	}

	audit.SetTarget(ctx, id)
	audit.Set(ctx, "requester_id", row.RequesterID)
	audit.Set(ctx, "target", row.TargetName)
	audit.Set(ctx, "username", row.Username)
	if s.cfg.Email.HasSMTP() {
		go s.notifyRequester(context.WithoutCancel(ctx), row)
	}
	return row, nil
}

// whyUndecided names what kept a request from being decided.
func whyUndecided(ctx context.Context, q *db.Queries, id, caller string) error {
	r, err := q.GetAccessRequest(ctx, id)
	switch {
	case err != nil:
		return err
	case r.RequesterID == caller:
		return newError(connect.CodePermissionDenied, "another admin has to answer your own request")
	}
	return newError(connect.CodeFailedPrecondition, "the request is "+r.Status+" already")
}

func (s *accessRequestService) CancelAccessRequest(
	ctx context.Context,
	req *nokkuv1.CancelAccessRequestRequest,
) (*nokkuv1.CancelAccessRequestResponse, error) {
	userID := actor.UserIDFromContext(ctx)
	if userID == "" {
		return nil, newError(connect.CodePermissionDenied, "only people ask for access, and only they cancel")
	}
	cancelled, err := s.cfg.Conn.Tenant().CancelAccessRequest(ctx, &db.CancelAccessRequestParams{
		ID:          req.GetId(),
		RequesterID: userID,
	})
	if err != nil {
		return nil, err
	}
	if cancelled == 0 {
		return nil, newError(connect.CodeFailedPrecondition, "only your own pending requests can be cancelled")
	}
	return &nokkuv1.CancelAccessRequestResponse{}, nil
}

func (s *accessRequestService) SetRequestableTags(
	ctx context.Context,
	req *nokkuv1.SetRequestableTagsRequest,
) (*nokkuv1.SetRequestableTagsResponse, error) {
	if err := s.cfg.Conn.Tenant().SetRequestableTags(ctx, req.GetTags()); err != nil {
		return nil, err
	}
	audit.Set(ctx, "tags", req.GetTags())
	return &nokkuv1.SetRequestableTagsResponse{}, nil
}

func (s *accessRequestService) notifyApprovers(ctx context.Context, r *db.AccessRequestDetail) {
	approvers, err := s.cfg.Conn.Tenant().ListApprovers(ctx, r.RequesterID)
	if err != nil {
		slog.Warn("approvers not notified", "error", err, "request_id", r.ID)
		return
	}
	for _, a := range approvers {
		if err := s.cfg.Email.SendAccessRequestEmail(ctx, email.AccessRequest{
			UserID:      a.ID,
			Email:       a.Email,
			RequesterID: r.RequesterID,
			RequestID:   r.ID,
			Requester:   cmp.Or(r.RequesterName, r.RequesterEmail),
			Target:      r.TargetName,
			Account:     r.Username,
			Reason:      r.Reason,
			URL:         requestURL(ctx, r.ID),
			Duration:    r.Duration,
		}); err != nil {
			slog.Warn("approver not notified", "error", err, "request_id", r.ID, "user_id", a.ID)
		}
	}
}

func (s *accessRequestService) notifyRequester(ctx context.Context, r *db.AccessRequestDetail) {
	if err := s.cfg.Email.SendAccessDecisionEmail(ctx, email.AccessDecision{
		UserID:    r.RequesterID,
		Email:     r.RequesterEmail,
		RequestID: r.ID,
		Decider:   r.DeciderName,
		Target:    r.TargetName,
		Account:   r.Username,
		URL:       requestURL(ctx, r.ID),
		Until:     r.GrantedUntil(),
	}); err != nil {
		slog.Warn("requester not notified", "error", err, "request_id", r.ID)
	}
}

func requestURL(ctx context.Context, id string) string {
	ws, _ := actor.WorkspaceFromContext(ctx)
	return ws.BaseURL + "/access/requests?id=" + id
}
