package api

import (
	"context"
	"time"

	"github.com/mizuchilabs/kata/buildinfo"
	"google.golang.org/protobuf/types/known/durationpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

type utilService struct {
	cfg *app.Config
}

func (s *utilService) GetVersion(
	_ context.Context,
	_ *nokkuv1.GetVersionRequest,
) (*nokkuv1.GetVersionResponse, error) {
	return &nokkuv1.GetVersionResponse{Version: &buildinfo.Version}, nil
}

func (s *utilService) GetInstanceInfo(
	ctx context.Context,
	_ *nokkuv1.GetInstanceInfoRequest,
) (*nokkuv1.GetInstanceInfoResponse, error) {
	op := s.cfg.Email.Operator
	signup := s.cfg.SaaS && actor.WorkspaceIDFromContext(ctx) == ""
	info := &nokkuv1.GetInstanceInfoResponse{
		OperatorName: &op.Name,
		SupportEmail: &op.SupportEmail,
		WebsiteUrl:   &op.WebsiteURL,
		TermsUrl:     &op.TermsURL,
		PrivacyUrl:   &op.PrivacyURL,
		ImprintUrl:   &op.ImprintURL,
		Hosted:       new(s.cfg.SaaS),
		Signup:       &signup,
	}
	if signup {
		info.WorkspaceDomain = new(s.cfg.Tenant.Domain())
	}
	return info, nil
}

func optDuration(d *durationpb.Duration) *time.Duration {
	if d == nil {
		return nil
	}
	return new(d.AsDuration())
}

// auditName runs before the change, so a delete keeps the name of what it removed.
func auditName(ctx context.Context, q *db.Queries, key, id string) error {
	names, err := q.GetNames(ctx, []string{id})
	if err != nil {
		return err
	}
	audit.Set(ctx, key, names[0])
	return nil
}
