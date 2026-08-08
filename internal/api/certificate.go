package api

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
	"github.com/nokku-sh/nokku/internal/pki"
	"github.com/nokku-sh/nokku/internal/ssh"
	"github.com/nokku-sh/nokku/internal/util"
)

type CertificateService struct {
	cfg *config.Config
}

func NewCertificateService(cfg *config.Config) *CertificateService {
	return &CertificateService{cfg: cfg}
}

func (s *CertificateService) CreateCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.CreateCertificateAuthorityRequest,
) (*nokkuv1.CreateCertificateAuthorityResponse, error) {
	meta.SetAuditWorkspaceID(ctx, req.GetWorkspaceId())

	if err := s.cfg.Billing.Check(
		ctx,
		req.GetWorkspaceId(),
		billing.ResourceCas,
	); err != nil {
		return nil, err
	}

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
		return nil, ErrInternal
	}

	userExtensions, err := util.ValidateExtensions(req.GetUserExtensions())
	if err != nil {
		return nil, NewError(connect.CodeInvalidArgument, "invalid extensions")
	}
	userCriticalOptions, err := util.ValidateCriticalOptions(req.GetUserCriticalOptions())
	if err != nil {
		return nil, NewError(connect.CodeInvalidArgument, "invalid critical options")
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
		return nil, DBError(err)
	}

	return &nokkuv1.CreateCertificateAuthorityResponse{
		CertificateAuthority: result.ToProto(),
	}, nil
}

func (s *CertificateService) GetCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.GetCertificateAuthorityRequest,
) (*nokkuv1.GetCertificateAuthorityResponse, error) {
	var ca *db.CertificateAuthority
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		if req.GetId() != "" {
			ca, err = q.GetCA(ctx, req.GetId())
			if err != nil {
				return err
			}
		}

		daemonID := meta.DaemonIDFromContext(ctx)
		if daemonID != "" {
			ca, err = q.GetCAByDaemonID(ctx, &daemonID)
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.GetCertificateAuthorityResponse{
		CertificateAuthority: ca.ToProto(),
	}, nil
}

func (s *CertificateService) ListCertificateAuthorities(
	ctx context.Context,
	req *nokkuv1.ListCertificateAuthoritiesRequest,
) (*nokkuv1.ListCertificateAuthoritiesResponse, error) {
	var result []*db.CertificateAuthority
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.ListCAs(ctx, &db.ListCAsParams{WorkspaceID: req.GetWorkspaceId()})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.ListCertificateAuthoritiesResponse{
		CertificateAuthorities: db.CAsToProto(result),
	}, nil
}

func (s *CertificateService) UpdateCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.UpdateCertificateAuthorityRequest,
) (*nokkuv1.UpdateCertificateAuthorityResponse, error) {
	userExtensions, err := util.ValidateExtensions(req.GetUserExtensions())
	if err != nil {
		return nil, NewError(connect.CodeInvalidArgument, "invalid extensions")
	}
	userCriticalOptions, err := util.ValidateCriticalOptions(req.GetUserCriticalOptions())
	if err != nil {
		return nil, NewError(connect.CodeInvalidArgument, "invalid critical options")
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
		Lifetime:            new(req.GetLifetime().AsDuration()),
		UserDefaultTtl:      new(req.GetUserDefaultTtl().AsDuration()),
		UserMaxTtl:          new(req.GetUserMaxTtl().AsDuration()),
		HostDefaultTtl:      new(req.GetHostDefaultTtl().AsDuration()),
		HostMaxTtl:          new(req.GetHostMaxTtl().AsDuration()),
	}

	var result *db.CertificateAuthority
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		var err error
		result, err = q.UpdateCA(ctx, params)
		if err != nil {
			return err
		}
		meta.SetAuditWorkspaceID(ctx, result.WorkspaceID)
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.UpdateCertificateAuthorityResponse{
		CertificateAuthority: result.ToProto(),
	}, nil
}

func (s *CertificateService) DeleteCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.DeleteCertificateAuthorityRequest,
) (*nokkuv1.DeleteCertificateAuthorityResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		ca, err := q.DeleteCA(ctx, req.GetId())
		if err != nil {
			return err
		}
		meta.SetAuditWorkspaceID(ctx, ca.WorkspaceID)
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.DeleteCertificateAuthorityResponse{}, nil
}

func (s *CertificateService) RolloverCertificateAuthority(
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

		// Generate the new root CA
		var newCA *ssh.CAInfo
		if ca.AuthorityType == nokkuv1.AuthorityType_AUTHORITY_TYPE_X509 {
			newCA, err = pki.NewCA(keyType, keyBits, ca.Lifetime)
		} else {
			newCA, err = ssh.NewCA(keyType, keyBits, ca.Lifetime)
		}
		if err != nil {
			return err
		}

		result, err = q.ReplaceCA(ctx, &db.ReplaceCAParams{
			CaID:         ca.ID,
			Certificate:  string(newCA.Certificate),
			PrivateKey:   newCA.PrivateKey,
			PublicKey:    newCA.PublicKey,
			SerialNumber: newCA.SerialNumber,
			Subject:      newCA.Subject,
			NotBefore:    newCA.NotBefore,
			NotAfter:     newCA.NotAfter,
			KeyType:      newCA.KeyType,
			KeyBits:      newCA.KeyBits,
		})
		if err != nil {
			return err
		}

		meta.SetAuditWorkspaceID(ctx, result.WorkspaceID)
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	// Skip notification if no rollover
	if result == nil {
		return &nokkuv1.RolloverCertificateAuthorityResponse{}, nil
	}

	s.cfg.Pool.Broadcast(result.WorkspaceID, &nokkuv1.Notification{
		EventType: nokkuv1.Notification_EVENT_TYPE_CERTIFICATES.Enum(),
	})
	return &nokkuv1.RolloverCertificateAuthorityResponse{
		CertificateAuthority: result.ToProto(),
	}, nil
}

func (s *CertificateService) SignSSHCertificate(
	ctx context.Context,
	req *nokkuv1.SignSSHCertificateRequest,
) (*nokkuv1.SignSSHCertificateResponse, error) {
	// By default id of the actor is the principal for user certificates
	actor := meta.ActorFromContext(ctx)
	keyID := fmt.Sprintf("nokku:login:%s:%s:%s", actor.Type, actor.Name, actor.ID)
	principal := actor.ID

	var ca *db.CertificateAuthority
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		// Fallback for CA
		if req.GetCaId() != "" {
			ca, err = q.GetCA(ctx, req.GetCaId())
			if err != nil {
				return err
			}
		} else if req.GetWorkspaceId() != "" {
			ca, err = q.GetDefaultCA(ctx, req.GetWorkspaceId())
			if err != nil {
				return err
			}
		}

		// Fallback for service account
		saID := meta.ServiceAccountIDFromContext(ctx)
		if saID != "" {
			saWSID, err := q.GetServiceAccountWorkspaceID(ctx, saID)
			if err != nil {
				return err
			}
			ca, err = q.GetDefaultCA(ctx, saWSID)
			if err != nil {
				return err
			}
		}

		// Daemons get automatically the correct CA
		daemonID := meta.DaemonIDFromContext(ctx)
		if daemonID != "" {
			ca, err = q.GetCAByDaemonID(ctx, &daemonID)
			if err != nil {
				return err
			}
		}

		meta.SetAuditWorkspaceID(ctx, ca.WorkspaceID)

		// Override principal if a host certificate was requested
		if req.GetType() == nokkuv1.SignSSHCertificateRequest_CERTIFICATE_TYPE_HOST {
			if daemonID != "" {
				target, err := q.GetTargetByDaemon(ctx, &daemonID)
				if err != nil {
					return err
				}
				principal = target.ID
			} else {
				// USER/SA: Must provide the Target ID manually
				if req.GetTargetId() == "" {
					return ErrInvalidInput // target_id is strictly required here
				}

				// Validate that this target actually exists
				target, err := q.GetTarget(ctx, req.GetTargetId())
				if err != nil {
					return err
				}

				principal = target.ID
			}
			keyID = fmt.Sprintf("nokku:provision:%s:%s:%s", actor.Type, actor.Name, actor.ID)
		}
		return nil
	}); err != nil {
		return nil, DBError(err)
	}
	if ca == nil {
		return nil, ErrNotFound
	}
	if ca.AuthorityType == nokkuv1.AuthorityType_AUTHORITY_TYPE_X509 {
		return nil, NewError(
			connect.CodeInvalidArgument,
			"certificate authority is not an SSH CA",
		)
	}

	cert, err := ssh.SignCertificate(
		ca,
		req.GetPublicKey(),
		principal,
		keyID,
		req.GetTtl().AsDuration(),
		req.GetType(),
	)
	if err != nil {
		return nil, NewError(connect.CodeInvalidArgument, err.Error())
	}

	expiry := util.Uint64ToUnixTime(cert.ValidBefore)
	return &nokkuv1.SignSSHCertificateResponse{
		CaId:              &ca.ID,
		CaName:            &ca.Name,
		CaPublicKey:       &ca.PublicKey,
		SignedCertificate: new(ssh.MarshalKey(cert)),
		ExpiresAt:         timestamppb.New(expiry),
	}, nil
}

func (s *CertificateService) SignX509Certificate(
	ctx context.Context,
	req *nokkuv1.SignX509CertificateRequest,
) (*nokkuv1.SignX509CertificateResponse, error) {
	if req.GetCaId() == "" {
		return nil, NewError(connect.CodeInvalidArgument, "ca_id is required")
	}

	var ca *db.CertificateAuthority
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		ca, err = q.GetCA(ctx, req.GetCaId())
		if err != nil {
			return err
		}
		meta.SetAuditWorkspaceID(ctx, ca.WorkspaceID)
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	if ca.AuthorityType != nokkuv1.AuthorityType_AUTHORITY_TYPE_X509 {
		return nil, NewError(
			connect.CodeInvalidArgument,
			"certificate authority is not an X.509 CA",
		)
	}
	if !ca.IsActive {
		return nil, NewError(
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
		return nil, NewError(connect.CodeInvalidArgument, err.Error())
	}

	return &nokkuv1.SignX509CertificateResponse{
		CaId:        &ca.ID,
		CaName:      &ca.Name,
		Certificate: new(string(certPEM)),
		CaChain:     &ca.Certificate,
		ExpiresAt:   timestamppb.New(expiresAt),
	}, nil
}
