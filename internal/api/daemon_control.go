package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	gossh "golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/config"
	nokkudaemon "github.com/nokku-sh/nokku/internal/daemon"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/recording"
	"github.com/nokku-sh/nokku/internal/ssh"
	"github.com/nokku-sh/nokku/internal/util"
)

const (
	quotaCheckInterval = 1 << 20 // 1 MiB

	// maxUploadBytes ends an upload. nokkud stops a recording at 50 MB, so
	// only a daemon that ignores that gets this far.
	maxUploadBytes = 64 << 20
)

// daemonControlService is everything a daemon calls. Authorization only lets
// daemons in, except for EnrollDaemon. Connect and DaemonRelay come from the
// embedded pool.
type daemonControlService struct {
	*nokkudaemon.Pool

	cfg *config.Config
}

func newDaemonControlService(cfg *config.Config) *daemonControlService {
	return &daemonControlService{Pool: cfg.Pool, cfg: cfg}
}

func (s *daemonControlService) EnrollDaemon(
	ctx context.Context,
	req *nokkuv1.EnrollDaemonRequest,
) (*nokkuv1.EnrollDaemonResponse, error) {
	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return nil, errInternal
	}
	// The session is bound to the daemon's DPoP key, so a stolen token is
	// useless without it.
	binding, err := s.enrollBinding(ctx, ci)
	if err != nil {
		return nil, err
	}

	out, err := nokkudaemon.Enroll(ctx, s.cfg.Conn, nokkudaemon.EnrollInput{
		Token:    req.GetToken(),
		Binding:  binding,
		Metadata: requestMetadata(ci.RequestHeader()),
		// The workspace is only known once the token verified, so the
		// resource cap is checked here instead of in the guard.
		CanCreate: func(ctx context.Context, workspaceID string) error {
			return s.cfg.Entitlements.CheckResources(ctx, workspaceID)
		},
	})
	if errors.Is(err, nokkudaemon.ErrEnrollToken) {
		return nil, newError(connect.CodeFailedPrecondition, err.Error())
	}
	if err != nil {
		return nil, err
	}
	workspaceID := out.WorkspaceID
	ctx = actor.AnnotateTenant(ctx, workspaceID)

	token, err := s.cfg.IAM.IssueDaemonSession(ctx, workspaceID, out.DaemonID, binding)
	if err != nil {
		return nil, errInternal
	}

	return &nokkuv1.EnrollDaemonResponse{
		Id:          &out.DaemonID,
		WorkspaceId: &workspaceID,
		TargetId:    &out.TargetID,
		Status:      &out.Status,
		Config:      out.Config,
		AccessToken: &token,
	}, nil
}

func (s *daemonControlService) SyncDaemon(
	ctx context.Context,
	req *nokkuv1.SyncDaemonRequest,
) (*nokkuv1.SyncDaemonResponse, error) {
	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return nil, errInternal
	}

	res, err := nokkudaemon.Sync(ctx, s.cfg.Conn, nokkudaemon.SyncInput{
		DaemonID:    actor.DaemonIDFromContext(ctx),
		Metadata:    requestMetadata(ci.RequestHeader()),
		ReqMetadata: req.GetMetadata(),
		Users:       req.GetUsers(),
		PrivateIPs:  req.GetPrivateIps(),
	})
	if err != nil {
		return nil, err
	}
	return &nokkuv1.SyncDaemonResponse{
		Status:        res.Status,
		Config:        res.Config,
		Principals:    res.Principals,
		CaPublicKey:   &res.CAPublicKey,
		RetiredCaKeys: res.RetiredCAs,
		StateVersion:  &res.Version,
	}, nil
}

// SignHostCertificate signs the daemon's host key for its own target, under
// the CA that target uses.
func (s *daemonControlService) SignHostCertificate(
	ctx context.Context,
	req *nokkuv1.SignHostCertificateRequest,
) (*nokkuv1.SignHostCertificateResponse, error) {
	daemonID := actor.DaemonIDFromContext(ctx)
	var ca *db.CertificateAuthority
	var target *db.Target
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		if ca, err = q.GetCAByDaemonID(ctx, &daemonID); err != nil {
			return err
		}
		target, err = q.GetTargetByDaemon(ctx, &daemonID)
		return err
	}); err != nil {
		return nil, err
	}
	if !ca.IsActive {
		return nil, newError(connect.CodeFailedPrecondition, "certificate authority is not active")
	}

	cert, err := ssh.SignCertificate(
		ca,
		req.GetPublicKey(),
		[]string{target.ID},
		"nokku:provision:daemon:"+daemonID,
		0,
		gossh.HostCert,
	)
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, err.Error())
	}

	audit.SetTarget(ctx, ca.ID)
	audit.Set(ctx, "serial", strconv.FormatUint(cert.Serial, 10))
	audit.Set(ctx, "key_id", cert.KeyId)
	audit.Set(ctx, "principals", cert.ValidPrincipals)
	audit.Set(ctx, "expires_at", util.Uint64ToUnixTime(cert.ValidBefore))
	return &nokkuv1.SignHostCertificateResponse{
		SignedCertificate: new(ssh.MarshalKey(cert)),
	}, nil
}

func (s *daemonControlService) UploadRecording(
	ctx context.Context,
	stream *connect.ClientStream[nokkuv1.UploadRecordingRequest],
) (*nokkuv1.UploadRecordingResponse, error) {
	daemonID := actor.DaemonIDFromContext(ctx)
	if daemonID == "" {
		return nil, newError(connect.CodePermissionDenied, "only daemons can upload recordings")
	}

	if !stream.Receive() {
		return nil, newError(connect.CodeInvalidArgument, "missing recording metadata")
	}
	meta := stream.Msg().GetMeta()
	if meta == nil || meta.GetRecordingId() == "" {
		return nil, newError(connect.CodeInvalidArgument, "missing recording metadata")
	}

	rec, workspaceID, err := s.resolveUpload(ctx, daemonID, meta)
	if err != nil {
		return nil, err
	}

	// A daemon that dies takes ctx with it, and a canceled ctx would drop the
	// object. What arrived by then is the evidence, so the writer outlives it.
	wctx, abort := context.WithCancel(context.WithoutCancel(ctx))
	defer abort()
	w, err := s.cfg.Record.NewWriter(wctx, rec)
	if err != nil {
		slog.Error("open recording object", "recording_id", rec.ID, "error", err)
		return nil, errInternal
	}

	var size int64
	var complete, tooLarge bool
	lastChecked := int64(0)
receive:
	for stream.Receive() {
		switch m := stream.Msg().GetMsg().(type) {
		case *nokkuv1.UploadRecordingRequest_Chunk:
			data := m.Chunk
			if len(data) == 0 {
				continue
			}
			if size+int64(len(data)) > maxUploadBytes {
				tooLarge = true
				break receive
			}
			// Evict the oldest recordings instead of blocking the stream.
			if size-lastChecked >= quotaCheckInterval {
				lastChecked = size
				if err := s.cfg.Record.EvictForBytes(ctx, workspaceID, rec.ID, size); err != nil {
					slog.Warn(
						"recording eviction sweep failed",
						"workspace_id", workspaceID,
						"recording_id", rec.ID,
						"error", err,
					)
				}
			}
			if err := w.WriteChunk(data); err != nil {
				_ = w.Close()
				slog.Error("write recording chunk", "recording_id", rec.ID, "error", err)
				return nil, errInternal
			}
			size += int64(len(data))
		case *nokkuv1.UploadRecordingRequest_Final:
			complete = true
		}
	}
	interrupted := stream.Err() != nil && !errors.Is(stream.Err(), io.EOF)
	if err = w.Close(); err != nil {
		slog.Error("commit recording object", "recording_id", rec.ID, "error", err)
		return nil, errInternal
	}

	// The row is closed for an interrupted upload too, or it would count as
	// a live session and as no bytes.
	rowCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := s.cfg.Conn.WithWorkspace(rowCtx, func(q *db.Queries) (err error) {
		rec, err = q.SetRecordingComplete(rowCtx, &db.SetRecordingCompleteParams{
			ID:        rec.ID,
			SizeBytes: size,
			Complete:  complete,
		})
		return err
	}); err != nil {
		return nil, err
	}

	switch {
	case tooLarge:
		// What arrived is kept as a cut recording. This code tells the daemon
		// not to send it again.
		return nil, newError(connect.CodeInvalidArgument, "recording is too large, the rest is cut")
	case complete:
		s.cfg.Record.ScrubRecording(rec)
	case interrupted:
		return nil, newError(connect.CodeUnknown, "recording stream interrupted")
	}

	return &nokkuv1.UploadRecordingResponse{
		RecordingId: &rec.ID,
		SizeBytes:   &size,
	}, nil
}

// resolveUpload resumes the recording when the daemon uploads its id again.
func (s *daemonControlService) resolveUpload(
	ctx context.Context,
	daemonID string,
	rm *nokkuv1.RecordingMeta,
) (*db.Recording, string, error) {
	var rec *db.Recording
	var workspaceID string
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		daemon, err := q.GetDaemon(ctx, daemonID)
		if err != nil {
			return err
		}
		workspaceID = daemon.WorkspaceID

		existing, err := q.GetRecording(ctx, rm.GetRecordingId())
		if err == nil {
			if existing.DaemonID == nil || *existing.DaemonID != daemonID {
				return errors.New("recording belongs to another daemon")
			}
			if existing.Complete {
				return newError(connect.CodeInvalidArgument, "recording is already finalized")
			}
			rec = existing
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		rec, err = q.CreateRecording(ctx, &db.CreateRecordingParams{
			ID:          rm.GetRecordingId(),
			WorkspaceID: workspaceID,
			DaemonID:    daemonID,
			Username:    rm.GetUsername(),
			Key:         recording.NewKey(),
		})
		return err
	}); err != nil {
		return nil, "", err
	}
	return rec, workspaceID, nil
}

// UnenrollDaemon removes the calling daemon and the session it called with.
func (s *daemonControlService) UnenrollDaemon(
	ctx context.Context,
	_ *nokkuv1.UnenrollDaemonRequest,
) (*nokkuv1.UnenrollDaemonResponse, error) {
	daemonID := actor.DaemonIDFromContext(ctx)
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		if _, err := q.DeleteDaemon(ctx, daemonID); err != nil {
			return err
		}
		_, err := q.DeleteSubjectSessions(ctx, daemonID)
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.UnenrollDaemonResponse{}, nil
}

// enrollBinding returns the DPoP key thumbprint. A missing proof is an error,
// daemons must enroll key-bound.
func (s *daemonControlService) enrollBinding(ctx context.Context, ci connect.CallInfo) (string, error) {
	svc := s.cfg.IAM
	if svc.DPoP == nil {
		return "", newError(connect.CodeUnimplemented, "DPoP is not configured")
	}

	binding, err := svc.DPoP.Verify(
		ctx,
		ci.RequestHeader().Get("DPoP"),
		"",
		http.MethodPost,
		s.cfg.FullURL()+nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure,
	)
	if err != nil {
		if errors.Is(err, iam.ErrDPoPNonce) {
			svc.AdvertiseDPoPNonce(ci.ResponseHeader())
			return "", newError(connect.CodeUnauthenticated, "stale DPoP nonce")
		}
		return "", newError(connect.CodeInvalidArgument, "invalid DPoP proof")
	}
	return binding, nil
}

func requestMetadata(h http.Header) []byte {
	metadata, _ := json.Marshal(map[string]string{
		"user-agent": h.Get("User-Agent"),
		"host":       h.Get("Host"),
	})
	return metadata
}
