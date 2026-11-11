package api

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
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
	// A leaked service account token leaves an hour of access, not days.
	serviceAccountCertTTL = time.Hour
	// For servers set up with nk sync, so a revoke lands within the hour.
	daemonlessCertTTL = time.Hour
)

type certificateService struct {
	cfg *config.Config
}

func (s *certificateService) GetCertificateAuthority(
	ctx context.Context,
	_ *nokkuv1.GetCertificateAuthorityRequest,
) (*nokkuv1.GetCertificateAuthorityResponse, error) {
	ca, err := s.cfg.Conn.Tenant().GetWorkspaceCA(ctx)
	if err != nil {
		return nil, err
	}

	return &nokkuv1.GetCertificateAuthorityResponse{
		CertificateAuthority: ca.ToProto(),
	}, nil
}

func (s *certificateService) UpdateCertificateAuthority(
	ctx context.Context,
	req *nokkuv1.UpdateCertificateAuthorityRequest,
) (*nokkuv1.UpdateCertificateAuthorityResponse, error) {
	if _, err := applyMask(req, req.GetUpdateMask()); err != nil {
		return nil, err
	}
	params := &db.UpdateCAParams{UserTtl: optDuration(req.GetUserTtl())}
	// Unset keeps what the CA has, empty takes the list away.
	if req.SourceAddress != nil {
		list, err := ssh.SourceAddresses(req.GetSourceAddress())
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err.Error())
		}
		params.SourceAddress = &list
	}

	result, err := s.cfg.Conn.Tenant().UpdateCA(ctx, params)
	if err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, result.ID)

	return &nokkuv1.UpdateCertificateAuthorityResponse{
		CertificateAuthority: result.ToProto(),
	}, nil
}

func (s *certificateService) RolloverCertificateAuthority(
	ctx context.Context,
	_ *nokkuv1.RolloverCertificateAuthorityRequest,
) (*nokkuv1.RolloverCertificateAuthorityResponse, error) {
	var result *db.SSHCA
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		ca, err := q.GetWorkspaceCAForUpdate(ctx)
		if err != nil {
			return err
		}
		result, err = ssh.Rollover(ctx, q, s.cfg.Keyset, ca)
		return err
	}); err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, result.ID)

	return &nokkuv1.RolloverCertificateAuthorityResponse{
		CertificateAuthority: result.ToProto(),
	}, nil
}

// SignSSHCertificate names current grants, so a revoked one ends with the cert.
func (s *certificateService) SignSSHCertificate(
	ctx context.Context,
	req *nokkuv1.SignSSHCertificateRequest,
) (*nokkuv1.SignSSHCertificateResponse, error) {
	caller, _ := actor.PrincipalFromContext(ctx)
	// A cookie must not sign any pasted key. People sign through nk.
	if caller.Kind == actor.KindUser {
		return nil, connect.NewError(connect.CodePermissionDenied, "sign certificates with nk or a service account")
	}
	// Someone with this machine's session must not mint a cert for a key they carry off.
	if caller.Kind == actor.KindCLI {
		key, err := ssh.NormalizeKey(req.GetPublicKey())
		if err != nil {
			return nil, err
		}
		if tok, ok := iam.CurrentToken(ctx); !ok || tok.SshKey != key {
			return nil, connect.NewError(connect.CodePermissionDenied,
				"this key is not the one this nk session signed in with, run nk logout, then nk login")
		}
	}

	var ca *db.SSHCA
	var signer gossh.Signer
	var limits ssh.Limits
	var principals []string
	// until is when the first grant ends, nil if none of them do.
	var until *time.Time
	var daemonless bool
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		// An unknown id answers like a missing grant, so ids can't be probed.
		denied := connect.NewError(connect.CodePermissionDenied, "you have no access to this server")
		target, err := q.GetTarget(ctx, req.GetTargetId())
		if errors.Is(err, pgx.ErrNoRows) {
			return denied
		}
		if err != nil {
			return err
		}
		// Grant first, so a member without one learns nothing of the server.
		accounts, err := q.ListSubjectUsernamesForTargets(ctx, &db.ListSubjectUsernamesForTargetsParams{
			TargetIds: []string{target.ID},
			SubjectID: caller.ID,
		})
		if err != nil {
			return err
		}
		if len(accounts) == 0 || !accounts[0].UserOk {
			return denied
		}
		// An unapproved daemon may hold old principals. No certs to match them.
		if !accounts[0].DaemonOk {
			return connect.NewError(connect.CodeFailedPrecondition, "the daemon of this server is not approved")
		}
		daemonless = target.DaemonID == nil
		for _, a := range accounts {
			principals = append(principals, login.Principal(caller.ID, target.ID, a.Username))
			// An nk sync server only takes a cert naming it and the account.
			if daemonless {
				principals = append(principals, login.ServerPrincipal(target.ID, a.Username))
			}
			if end := a.Until(); end != nil && (until == nil || end.Before(*until)) {
				until = end
			}
		}
		if ca, err = q.GetWorkspaceCA(ctx); err != nil {
			return err
		}
		if signer, err = ssh.CASigner(ctx, q, s.cfg.Keyset, ca.ID, gossh.UserCert); err != nil {
			return err
		}
		limits = ssh.Limits{SourceAddress: ca.SourceAddress}
		// Machines get their own limits, a CA office list would block runners.
		if caller.Kind == actor.KindServiceAccount {
			account, err := q.GetServiceAccount(ctx, caller.ID)
			if err != nil {
				return err
			}
			limits = ssh.Limits{ForceCommand: account.ForceCommand, SourceAddress: account.SourceAddress}
		}
		return q.TouchAccessUsage(ctx, &db.TouchAccessUsageParams{TargetID: target.ID, SubjectID: caller.ID})
	}); err != nil {
		return nil, err
	}
	// The workspace's lifetime, and everything below only shortens it.
	ttl := ca.UserTtl
	// No certificate outlives the key or the nk session it was asked with.
	tok, _ := iam.CurrentToken(ctx)
	if caller.Kind == actor.KindServiceAccount {
		// The cap follows the token the account called with, not the account.
		ttl = min(ttl, serviceAccountCertTTL)
	}
	if ttl = untilTokenEnds(ttl, tok.ExpiresAt); ttl <= 0 {
		return nil, connect.NewError(connect.CodeUnauthenticated, "the token has expired")
	}
	if until != nil {
		// The certificate never outlives its first grant to end.
		ttl = min(ttl, time.Until(*until))
		if ttl <= 0 {
			return nil, connect.NewError(connect.CodePermissionDenied, "you have no access to this server")
		}
	}
	if daemonless {
		// No revoke reaches such a server, only expiry ends the access.
		ttl = min(ttl, daemonlessCertTTL)
	}

	cert, err := ssh.SignCertificate(
		ca,
		signer,
		req.GetPublicKey(),
		principals,
		fmt.Sprintf("nokku:login:%s:%s", caller.Kind, caller.ID),
		ttl,
		gossh.UserCert,
		limits,
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
	// The event is the cert's only record, written before anyone holds one.
	if err := s.cfg.Audit.Commit(ctx); err != nil {
		return nil, err
	}
	return &nokkuv1.SignSSHCertificateResponse{
		SignedCertificate: new(ssh.MarshalKey(cert)),
		ExpiresAt:         timestamppb.New(expiry),
	}, nil
}

// untilTokenEnds keeps the certificate from outliving the token.
func untilTokenEnds(ttl time.Duration, tokenExpiresAt *time.Time) time.Duration {
	if tokenExpiresAt != nil {
		ttl = min(ttl, time.Until(*tokenExpiresAt))
	}
	return ttl
}
