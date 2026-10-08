package api

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/audit"

	"connectrpc.com/connect"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/ssh"
)

// serviceAccountCertTTL is the most a service account's certificate lives. A
// job signs a fresh one when it runs, so a leaked token leaves an hour of
// access behind and not days.
const serviceAccountCertTTL = time.Hour

type certificateService struct {
	cfg *config.Config
}

func (s *certificateService) CreateCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.CreateCertificateAuthorityRequest,
) (*nokkuv1.CreateCertificateAuthorityResponse, error) {
	ca, err := ssh.NewCA(req.GetKeyType(), req.GetKeyBits(), req.GetLifetime().AsDuration())
	if err != nil {
		slog.Error("failed to generate CA", "error", err)
		return nil, errInternal
	}

	userExtensions, err := db.ValidateExtensions(req.GetUserExtensions())
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, "invalid extensions")
	}
	userCriticalOptions, err := db.ValidateCriticalOptions(req.GetUserCriticalOptions())
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, "invalid critical options")
	}

	params := &db.CreateCAParams{
		Name:                req.GetName(),
		Description:         req.Description,
		PrivateKey:          ca.PrivateKey,
		PublicKey:           ca.PublicKey,
		NotBefore:           ca.NotBefore,
		NotAfter:            ca.NotAfter,
		KeyType:             ca.KeyType,
		KeyBits:             ca.KeyBits,
		UserExtensions:      userExtensions,
		UserCriticalOptions: userCriticalOptions,
		Lifetime:            req.GetLifetime().AsDuration(),
		AllowedKeyTypes:     req.GetAllowedKeyTypes(),
	}
	if req.GetUserDefaultTtl() != nil {
		params.UserDefaultTtl = req.GetUserDefaultTtl().AsDuration()
	}
	if req.GetUserMaxTtl() != nil {
		params.UserMaxTtl = req.GetUserMaxTtl().AsDuration()
	}
	if req.GetHostDefaultTtl() != nil {
		params.HostDefaultTtl = req.GetHostDefaultTtl().AsDuration()
	}
	if req.GetHostMaxTtl() != nil {
		params.HostMaxTtl = req.GetHostMaxTtl().AsDuration()
	}

	var result *db.SSHCA
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if result, err = q.CreateCA(ctx, params); err != nil {
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
	result, err := s.cfg.Conn.Tenant().ListCAs(ctx, &db.ListCAsParams{})
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
	userExtensions, err := db.ValidateExtensions(req.GetUserExtensions())
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, "invalid extensions")
	}
	userCriticalOptions, err := db.ValidateCriticalOptions(req.GetUserCriticalOptions())
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, "invalid critical options")
	}

	params := &db.UpdateCAParams{
		CaID:                req.GetId(),
		Name:                req.Name,
		Description:         req.Description,
		IsActive:            req.IsActive,
		UserExtensions:      userExtensions,
		UserCriticalOptions: userCriticalOptions,
		AllowedKeyTypes:     req.GetAllowedKeyTypes(),
		Lifetime:            optDuration(req.GetLifetime()),
		UserDefaultTtl:      optDuration(req.GetUserDefaultTtl()),
		UserMaxTtl:          optDuration(req.GetUserMaxTtl()),
		HostDefaultTtl:      optDuration(req.GetHostDefaultTtl()),
		HostMaxTtl:          optDuration(req.GetHostMaxTtl()),
	}

	// Only becoming the default moves it. Unsetting it leaves the workspace
	// without one, which the enroll fallback and the UI both handle.
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

		keyType := ca.KeyType
		if req.KeyType != nil {
			keyType = req.GetKeyType()
		}
		keyBits := ca.KeyBits
		if req.KeyBits != nil {
			keyBits = req.GetKeyBits()
		}
		result, err = ssh.Rollover(ctx, q, ca, keyType, keyBits, req.GetRevokePrevious())
		return err
	}); err != nil {
		return nil, err
	}
	audit.Set(ctx, "revoke_previous", req.GetRevokePrevious())

	return &nokkuv1.RolloverCertificateAuthorityResponse{
		CertificateAuthority: result.ToProto(),
	}, nil
}

// SignSSHCertificate signs a user certificate for the caller, for one server.
// It names the accounts the caller is granted there right now, so it works
// nowhere else and a revoked grant ends with it, even on a host that never
// hears of the revoke.
func (s *certificateService) SignSSHCertificate(
	ctx context.Context,
	req *nokkuv1.SignSSHCertificateRequest,
) (*nokkuv1.SignSSHCertificateResponse, error) {
	caller, _ := actor.PrincipalFromContext(ctx)

	var ca *db.SSHCA
	var principals []string
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		target, err := q.GetTarget(ctx, req.GetTargetId())
		if err != nil {
			return err
		}
		// The grant comes first, so a member without one learns nothing
		// about the server.
		accounts, err := q.ListSubjectUsernamesForTargets(ctx, &db.ListSubjectUsernamesForTargetsParams{
			TargetIds: []string{target.ID},
			SubjectID: &caller.ID,
		})
		if err != nil {
			return err
		}
		if len(accounts) == 0 {
			return newError(connect.CodePermissionDenied, "you have no access to this server")
		}
		for _, a := range accounts {
			principals = append(principals, ssh.LoginPrincipal(caller.ID, target.ID, a.Username))
		}
		// A daemon that is not approved, or no longer, may still hold the
		// principals of its last sync. It gets no new certificates to match.
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
		ca, err = q.GetCA(ctx, *target.CaID)
		return err
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

// serviceAccountTTL keeps the certificate from outliving the token.
func serviceAccountTTL(ca *db.SSHCA, ttl time.Duration, tokenExpiresAt *time.Time) time.Duration {
	ttl = min(ssh.UserTTL(ca, ttl), serviceAccountCertTTL)
	if tokenExpiresAt != nil {
		ttl = min(ttl, time.Until(*tokenExpiresAt))
	}
	return ttl
}
