package api

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"

	"connectrpc.com/connect/v2"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/ssh"
)

// serviceAccountCertTTL caps a service account's certificate, so a leaked token leaves an hour of access, not days.
const serviceAccountCertTTL = time.Hour

type certificateService struct {
	cfg *config.Config
}

func (s *certificateService) CreateCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.CreateCertificateAuthorityRequest,
) (*nokkuv1.CreateCertificateAuthorityResponse, error) {
	ca, err := ssh.NewCA()
	if err != nil {
		slog.Error("failed to generate CA", "error", err)
		return nil, errInternal
	}

	if ca.SourceAddress, err = ssh.SourceAddresses(req.GetSourceAddress()); err != nil {
		return nil, newError(connect.CodeInvalidArgument, err.Error())
	}
	ca.ForceCommand = strings.TrimSpace(req.GetForceCommand())
	ca.Name, ca.Description = req.GetName(), req.Description
	if req.GetUserDefaultTtl() != nil {
		ca.UserDefaultTtl = req.GetUserDefaultTtl().AsDuration()
	}
	if req.GetUserMaxTtl() != nil {
		ca.UserMaxTtl = req.GetUserMaxTtl().AsDuration()
	}
	if req.GetHostDefaultTtl() != nil {
		ca.HostDefaultTtl = req.GetHostDefaultTtl().AsDuration()
	}
	if req.GetHostMaxTtl() != nil {
		ca.HostMaxTtl = req.GetHostMaxTtl().AsDuration()
	}

	var result *db.SSHCA
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if result, err = q.CreateCA(ctx, ca); err != nil {
			return err
		}
		if !req.GetIsDefault() {
			return nil
		}
		result.IsDefault = true
		return q.SetDefaultCA(ctx, result.ID)
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.CreateCertificateAuthorityResponse{
		CertificateAuthority: result.ToProto(),
	}, nil
}

func (s *certificateService) GetCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.GetCertificateAuthorityRequest,
) (*nokkuv1.GetCertificateAuthorityResponse, error) {
	ca, err := s.cfg.Conn.Tenant().GetCA(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	return &nokkuv1.GetCertificateAuthorityResponse{
		CertificateAuthority: ca.ToProto(),
	}, nil
}

func (s *certificateService) ListCertificateAuthorities(
	ctx context.Context,
	_ *nokkuv1.ListCertificateAuthoritiesRequest,
) (*nokkuv1.ListCertificateAuthoritiesResponse, error) {
	result, err := s.cfg.Conn.Tenant().ListCAs(ctx)
	if err != nil {
		return nil, err
	}

	return &nokkuv1.ListCertificateAuthoritiesResponse{
		CertificateAuthorities: db.CAsToProto(result),
	}, nil
}

func (s *certificateService) UpdateCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.UpdateCertificateAuthorityRequest,
) (*nokkuv1.UpdateCertificateAuthorityResponse, error) {
	params := &db.UpdateCAParams{
		CaID:           req.GetId(),
		Name:           req.Name,
		Description:    req.Description,
		IsActive:       req.IsActive,
		UserDefaultTtl: optDuration(req.GetUserDefaultTtl()),
		UserMaxTtl:     optDuration(req.GetUserMaxTtl()),
		HostDefaultTtl: optDuration(req.GetHostDefaultTtl()),
		HostMaxTtl:     optDuration(req.GetHostMaxTtl()),
	}
	// Unset keeps what the CA has, empty takes the restriction away.
	if req.ForceCommand != nil {
		params.ForceCommand = new(strings.TrimSpace(req.GetForceCommand()))
	}
	if req.SourceAddress != nil {
		list, err := ssh.SourceAddresses(req.GetSourceAddress())
		if err != nil {
			return nil, newError(connect.CodeInvalidArgument, err.Error())
		}
		params.SourceAddress = &list
	}

	// Only becoming the default moves it. Unsetting leaves none, which the enroll fallback and the UI handle.
	var result *db.SSHCA
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if result, err = q.UpdateCA(ctx, params); err != nil {
			return err
		}
		if !req.GetIsDefault() || result.IsDefault {
			return nil
		}
		result.IsDefault = true
		return q.SetDefaultCA(ctx, result.ID)
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.UpdateCertificateAuthorityResponse{
		CertificateAuthority: result.ToProto(),
	}, nil
}

func (s *certificateService) DeleteCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.DeleteCertificateAuthorityRequest,
) (*nokkuv1.DeleteCertificateAuthorityResponse, error) {
	if _, err := s.cfg.Conn.Tenant().DeleteCA(ctx, req.GetId()); err != nil {
		return nil, err
	}

	return &nokkuv1.DeleteCertificateAuthorityResponse{}, nil
}

func (s *certificateService) RolloverCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.RolloverCertificateAuthorityRequest,
) (*nokkuv1.RolloverCertificateAuthorityResponse, error) {
	var result *db.SSHCA
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		ca, err := q.GetCAForUpdate(ctx, req.GetId())
		if err != nil {
			return err
		}
		result, err = ssh.Rollover(ctx, q, ca, req.GetRevokePrevious())
		return err
	}); err != nil {
		return nil, err
	}
	audit.Set(ctx, "revoke_previous", req.GetRevokePrevious())

	return &nokkuv1.RolloverCertificateAuthorityResponse{
		CertificateAuthority: result.ToProto(),
	}, nil
}

// SignSSHCertificate names the accounts the caller is granted on one server right now, so a revoked grant ends with it.
func (s *certificateService) SignSSHCertificate(
	ctx context.Context,
	req *nokkuv1.SignSSHCertificateRequest,
) (*nokkuv1.SignSSHCertificateResponse, error) {
	caller, _ := actor.PrincipalFromContext(ctx)

	var ca *db.SSHCA
	var principals []string
	// until is when the first grant in the certificate ends, nil when all of them are for good.
	var until *time.Time
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		target, err := q.GetTarget(ctx, req.GetTargetId())
		if err != nil {
			return err
		}
		// The grant comes first, so a member without one learns nothing about the server.
		accounts, err := q.ListSubjectUsernamesForTargets(ctx, &db.ListSubjectUsernamesForTargetsParams{
			TargetIds: []string{target.ID},
			SubjectID: caller.ID,
		})
		if err != nil {
			return err
		}
		if len(accounts) == 0 {
			return newError(connect.CodePermissionDenied, "you have no access to this server")
		}
		for _, a := range accounts {
			principals = append(principals, ssh.LoginPrincipal(caller.ID, target.ID, a.Username))
			if end := a.Until(); end != nil && (until == nil || end.Before(*until)) {
				until = end
			}
		}
		// A daemon that is not approved may still hold the principals of its last sync. It gets no certificates to match.
		if target.DaemonID != nil {
			daemon, err := q.GetDaemon(ctx, *target.DaemonID)
			if err != nil {
				return err
			}
			if daemon.Status != nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
				return newError(connect.CodeFailedPrecondition, "the daemon of this server is not approved")
			}
		}
		if target.CaID == nil {
			return newError(connect.CodeFailedPrecondition, "this server has no certificate authority")
		}
		if ca, err = q.GetCA(ctx, *target.CaID); err != nil {
			return err
		}
		return q.TouchAccessUsage(ctx, &db.TouchAccessUsageParams{TargetID: target.ID, SubjectID: caller.ID})
	}); err != nil {
		return nil, err
	}
	if !ca.IsActive {
		return nil, newError(
			connect.CodeFailedPrecondition,
			"certificate authority is not active",
		)
	}

	ttl := req.GetTtl().AsDuration()
	if caller.Kind == actor.KindServiceAccount {
		// The cap follows the token the account called with, not the account.
		tok, _ := iam.CurrentToken(ctx)
		ttl = serviceAccountTTL(ca, ttl, tok.ExpiresAt)
		// Nothing left would sign for the CA default.
		if ttl <= 0 {
			return nil, newError(connect.CodeUnauthenticated, "the token has expired")
		}
	}
	if until != nil {
		ttl = grantTTL(ca, ttl, *until)
		if ttl <= 0 {
			return nil, newError(connect.CodePermissionDenied, "you have no access to this server")
		}
	}

	cert, err := ssh.SignCertificate(
		ca,
		req.GetPublicKey(),
		principals,
		fmt.Sprintf("nokku:login:%s:%s", caller.Kind, caller.ID),
		ttl,
		gossh.UserCert,
	)
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, err.Error())
	}

	expiry := ssh.TimeFromUnix(cert.ValidBefore)
	audit.SetTarget(ctx, ca.ID)
	audit.Set(ctx, "serial", strconv.FormatUint(cert.Serial, 10))
	audit.Set(ctx, "key_id", cert.KeyId)
	audit.Set(ctx, "principals", cert.ValidPrincipals)
	audit.Set(ctx, "expires_at", expiry)
	return &nokkuv1.SignSSHCertificateResponse{
		CaId:              &ca.ID,
		CaName:            &ca.Name,
		CaPublicKey:       &ca.PublicKey,
		SignedCertificate: new(ssh.MarshalKey(cert)),
		ExpiresAt:         timestamppb.New(expiry),
	}, nil
}

// grantTTL keeps the certificate from outliving the first grant in it that ends.
func grantTTL(ca *db.SSHCA, ttl time.Duration, until time.Time) time.Duration {
	return min(ssh.UserTTL(ca, ttl), time.Until(until))
}

// serviceAccountTTL keeps the certificate from outliving the token.
func serviceAccountTTL(ca *db.SSHCA, ttl time.Duration, tokenExpiresAt *time.Time) time.Duration {
	ttl = min(ssh.UserTTL(ca, ttl), serviceAccountCertTTL)
	if tokenExpiresAt != nil {
		ttl = min(ttl, time.Until(*tokenExpiresAt))
	}
	return ttl
}
