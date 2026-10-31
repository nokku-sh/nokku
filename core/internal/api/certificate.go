package api

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"

	"connectrpc.com/connect/v2"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/ssh"
)

const (
	// serviceAccountCertTTL caps a service account's certificate, so a leaked token leaves an hour of access, not days.
	serviceAccountCertTTL = time.Hour
	// daemonlessCertTTL caps a certificate for a server set up with nk sync, so a revoke lands there within the hour.
	daemonlessCertTTL = time.Hour
)

type certificateService struct {
	cfg *config.Config
}

func (s *certificateService) CreateCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.CreateCertificateAuthorityRequest,
) (*nokkuv1.CreateCertificateAuthorityResponse, error) {
	source, err := ssh.SourceAddresses(req.GetSourceAddress())
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, err.Error())
	}
	ca := ssh.NewCA()
	ca.SourceAddress = source
	ca.ForceCommand = strings.TrimSpace(req.GetForceCommand())
	ca.Name, ca.Description = req.GetName(), req.Description
	if req.GetUserDefaultTtl() != nil {
		ca.UserDefaultTtl = req.GetUserDefaultTtl().AsDuration()
	}
	if req.GetUserMaxTtl() != nil {
		ca.UserMaxTtl = req.GetUserMaxTtl().AsDuration()
	}
	if req.GetHostTtl() != nil {
		ca.HostTtl = req.GetHostTtl().AsDuration()
	}

	var result *db.SSHCA
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if result, err = ssh.CreateCA(ctx, q, s.cfg.Keyset, ca); err != nil {
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
	if _, err := applyMask(req, req.GetUpdateMask()); err != nil {
		return nil, err
	}
	params := &db.UpdateCAParams{
		CaID:           req.GetId(),
		Name:           req.Name,
		Description:    req.Description,
		UserDefaultTtl: optDuration(req.GetUserDefaultTtl()),
		UserMaxTtl:     optDuration(req.GetUserMaxTtl()),
		HostTtl:        optDuration(req.GetHostTtl()),
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

	// Only becoming the default moves it, so a workspace never ends up without one.
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
	// The lock keeps the CA from becoming the default between the check and the delete.
	err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		ca, err := q.GetCAForUpdate(ctx, req.GetId())
		if err != nil {
			return err
		}
		// Servers and enroll tokens without a CA of their own fall back to the default.
		if ca.IsDefault {
			return newError(connect.CodeFailedPrecondition, "make another certificate authority the default first")
		}
		_, err = q.DeleteCA(ctx, ca.ID)
		return err
	})
	if db.IsRestrictViolation(err) {
		return nil, newError(
			connect.CodeFailedPrecondition,
			"servers still use this certificate authority, move them first",
		)
	}
	if err != nil {
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
		result, err = ssh.Rollover(ctx, q, s.cfg.Keyset, ca, req.GetRevokePrevious())
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
	// A browser cookie must not turn into a certificate for any key it pastes. People sign through nk.
	if caller.Kind == actor.KindUser {
		return nil, newError(connect.CodePermissionDenied, "sign certificates with nk or a service account")
	}

	var ca *db.SSHCA
	var signer gossh.Signer
	var principals []string
	// until is when the first grant in the certificate ends, nil when all of them are for good.
	var until *time.Time
	var daemonless bool
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
		if len(accounts) == 0 || !accounts[0].UserOk {
			return newError(connect.CodePermissionDenied, "you have no access to this server")
		}
		// A daemon that is not approved may still hold the principals of its last sync. It gets no certificates to match.
		if !accounts[0].DaemonOk {
			return newError(connect.CodeFailedPrecondition, "the daemon of this server is not approved")
		}
		daemonless = target.DaemonID == nil
		for _, a := range accounts {
			principals = append(principals, login.Principal(caller.ID, target.ID, a.Username))
			// A server set up with nk sync has one fixed rule, it takes a certificate that names it and the account.
			if daemonless {
				principals = append(principals, login.ServerPrincipal(target.ID, a.Username))
			}
			if end := a.Until(); end != nil && (until == nil || end.Before(*until)) {
				until = end
			}
		}
		if ca, err = q.GetCA(ctx, target.CaID); err != nil {
			return err
		}
		if signer, err = ssh.CASigner(ctx, q, s.cfg.Keyset, ca.ID, gossh.UserCert); err != nil {
			return err
		}
		return q.TouchAccessUsage(ctx, &db.TouchAccessUsageParams{TargetID: target.ID, SubjectID: caller.ID})
	}); err != nil {
		return nil, err
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
	if daemonless {
		// Nothing tells such a server about a revoke, the certificate running out is what ends the access.
		ttl = min(ssh.UserTTL(ca, ttl), daemonlessCertTTL)
	}

	cert, err := ssh.SignCertificate(
		ca,
		signer,
		req.GetPublicKey(),
		principals,
		fmt.Sprintf("nokku:login:%s:%s", caller.Kind, caller.ID),
		ttl,
		gossh.UserCert,
	)
	if err != nil {
		return nil, err
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
