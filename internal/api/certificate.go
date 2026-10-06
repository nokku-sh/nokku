package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"slices"
	"strconv"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/audit"

	"connectrpc.com/connect"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/pki"
	"github.com/nokku-sh/nokku/internal/ssh"
	"github.com/nokku-sh/nokku/internal/util"
)

type certificateService struct {
	cfg *config.Config
}

func newCertificateService(cfg *config.Config) *certificateService {
	return &certificateService{cfg: cfg}
}

func (s *certificateService) CreateCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.CreateCertificateAuthorityRequest,
) (*nokkuv1.CreateCertificateAuthorityResponse, error) {
	authorityType := req.GetAuthorityType()
	if authorityType == nokkuv1.AuthorityType_AUTHORITY_TYPE_UNSPECIFIED {
		authorityType = nokkuv1.AuthorityType_AUTHORITY_TYPE_SSH
	}

	var ca *ssh.CAInfo
	var err error
	if authorityType == nokkuv1.AuthorityType_AUTHORITY_TYPE_X509 {
		ca, err = pki.NewCA(
			req.GetKeyType(),
			req.GetKeyBits(),
			req.GetLifetime().AsDuration(),
		)
	} else {
		ca, err = ssh.NewCA(
			req.GetKeyType(),
			req.GetKeyBits(),
			req.GetLifetime().AsDuration(),
		)
	}
	if err != nil {
		slog.Error("failed to generate CA", "error", err)
		return nil, errInternal
	}

	userExtensions, err := util.ValidateExtensions(req.GetUserExtensions())
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, "invalid extensions")
	}
	userCriticalOptions, err := util.ValidateCriticalOptions(req.GetUserCriticalOptions())
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, "invalid critical options")
	}

	params := &db.CreateCAParams{
		WorkspaceID:         req.GetWorkspaceId(),
		Name:                req.GetName(),
		Description:         req.Description,
		IsDefault:           req.GetIsDefault(),
		Certificate:         string(ca.Certificate),
		PrivateKey:          ca.PrivateKey,
		PublicKey:           ca.PublicKey,
		SerialNumber:        ca.SerialNumber,
		Subject:             ca.Subject,
		NotBefore:           ca.NotBefore,
		NotAfter:            ca.NotAfter,
		KeyType:             ca.KeyType,
		AuthorityType:       authorityType,
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

	var result *db.CertificateAuthority
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		result, err = q.CreateCA(ctx, params)
		return err
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
	var ca *db.CertificateAuthority
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		ca, err = q.GetCA(ctx, req.GetId())
		return err
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.GetCertificateAuthorityResponse{
		CertificateAuthority: ca.ToProto(),
	}, nil
}

func (s *certificateService) ListCertificateAuthorities(
	ctx context.Context,
	req *nokkuv1.ListCertificateAuthoritiesRequest,
) (*nokkuv1.ListCertificateAuthoritiesResponse, error) {
	var result []*db.CertificateAuthority
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.ListCAs(ctx, &db.ListCAsParams{WorkspaceID: req.GetWorkspaceId()})
		return err
	}); err != nil {
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
	userExtensions, err := util.ValidateExtensions(req.GetUserExtensions())
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, "invalid extensions")
	}
	userCriticalOptions, err := util.ValidateCriticalOptions(req.GetUserCriticalOptions())
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, "invalid critical options")
	}

	params := &db.UpdateCAParams{
		CaID:                req.GetId(),
		Name:                req.Name,
		Description:         req.Description,
		IsActive:            req.IsActive,
		IsDefault:           req.IsDefault,
		UserExtensions:      userExtensions,
		UserCriticalOptions: userCriticalOptions,
		AllowedKeyTypes:     req.GetAllowedKeyTypes(),
		Lifetime:            optDuration(req.GetLifetime()),
		UserDefaultTtl:      optDuration(req.GetUserDefaultTtl()),
		UserMaxTtl:          optDuration(req.GetUserMaxTtl()),
		HostDefaultTtl:      optDuration(req.GetHostDefaultTtl()),
		HostMaxTtl:          optDuration(req.GetHostMaxTtl()),
	}

	var result *db.CertificateAuthority
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.UpdateCA(ctx, params)
		return err
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
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		_, err := q.DeleteCA(ctx, req.GetId())
		return err
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.DeleteCertificateAuthorityResponse{}, nil
}

func (s *certificateService) RolloverCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.RolloverCertificateAuthorityRequest,
) (*nokkuv1.RolloverCertificateAuthorityResponse, error) {
	var result *db.CertificateAuthority
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
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
		result, err = pki.Rollover(ctx, q, ca, keyType, keyBits, req.GetRevokePrevious())
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

	var ca *db.CertificateAuthority
	var principals []string
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
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
	if ca.AuthorityType != nokkuv1.AuthorityType_AUTHORITY_TYPE_SSH {
		return nil, errNotSSHCA
	}

	cert, err := ssh.SignCertificate(
		ca,
		req.GetPublicKey(),
		principals,
		fmt.Sprintf("nokku:login:%s:%s", caller.Kind, caller.ID),
		req.GetTtl().AsDuration(),
		gossh.UserCert,
	)
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, err.Error())
	}

	expiry := util.Uint64ToUnixTime(cert.ValidBefore)
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

func (s *certificateService) SignX509Certificate(
	ctx context.Context,
	req *nokkuv1.SignX509CertificateRequest,
) (*nokkuv1.SignX509CertificateResponse, error) {
	var ca *db.CertificateAuthority
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		switch {
		case req.GetCaId() != "":
			ca, err = q.GetCA(ctx, req.GetCaId())
		case req.GetWorkspaceId() != "":
			ca, err = q.GetDefaultCA(ctx, &db.GetDefaultCAParams{
				WorkspaceID:   req.GetWorkspaceId(),
				AuthorityType: nokkuv1.AuthorityType_AUTHORITY_TYPE_X509,
			})
		}
		return err
	}); err != nil {
		return nil, err
	}
	if ca == nil {
		return nil, errNotFound
	}

	if ca.AuthorityType != nokkuv1.AuthorityType_AUTHORITY_TYPE_X509 {
		return nil, newError(
			connect.CodeInvalidArgument,
			"certificate authority is not an X.509 CA",
		)
	}
	if !ca.IsActive {
		return nil, newError(
			connect.CodeFailedPrecondition,
			"certificate authority is not active",
		)
	}

	certPEM, expiresAt, err := pki.SignCertificate(
		ca,
		req.GetCsr(),
		req.GetUsage(),
		req.GetTtl().AsDuration(),
	)
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, err.Error())
	}

	audit.SetTarget(ctx, ca.ID)
	audit.Set(ctx, "usage", req.GetUsage().String())
	audit.Set(ctx, "expires_at", expiresAt)
	if block, _ := pem.Decode(certPEM); block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			sans := slices.Concat(cert.DNSNames, cert.EmailAddresses)
			for _, ip := range cert.IPAddresses {
				sans = append(sans, ip.String())
			}
			for _, uri := range cert.URIs {
				sans = append(sans, uri.String())
			}
			audit.Set(ctx, "subject", cert.Subject.String())
			audit.Set(ctx, "sans", sans)
		}
	}
	return &nokkuv1.SignX509CertificateResponse{
		CaId:        &ca.ID,
		CaName:      &ca.Name,
		Certificate: new(string(certPEM)),
		CaChain:     &ca.Certificate,
		ExpiresAt:   timestamppb.New(expiresAt),
	}, nil
}

// requireSSHCA keeps an X.509 CA off a server or an enroll token. No id means
// the workspace default, which is picked by kind.
func requireSSHCA(ctx context.Context, q *db.Queries, caID string) error {
	if caID == "" {
		return nil
	}
	ca, err := q.GetCA(ctx, caID)
	if err != nil {
		return err
	}
	if ca.AuthorityType != nokkuv1.AuthorityType_AUTHORITY_TYPE_SSH {
		return errNotSSHCA
	}
	return nil
}
