package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	gossh "golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/dpop"
	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/config"
	nokkudaemon "github.com/nokku-sh/nokku/core/internal/daemon"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/recording"
	"github.com/nokku-sh/nokku/core/internal/ssh"
)

const (
	// maxUploadBytes ends an upload. nokkud stops a recording at 50 MB, so only a daemon that ignores that gets here.
	maxUploadBytes = 64 << 20

	// maxOpenUploads bounds what one bad daemon costs. Every live session holds an upload open, which keeps up to 26 MiB
	// of core memory on its way to a bucket and only counts toward the storage cap once stored. A try over the limit
	// waits for its retry and loses nothing, the file stays on the daemon.
	maxOpenUploads = 64

	// storeTimeout bounds the commit and the transaction after it, each on its own.
	storeTimeout = 30 * time.Second
)

// errRecordingFinalized tells the daemon the core holds the whole recording, so its copy can go.
var errRecordingFinalized = connect.NewError(connect.CodeAlreadyExists, "recording is already finalized")

// daemonControlService is everything a daemon calls. Connect and DaemonRelay come from the embedded pool.
type daemonControlService struct {
	*nokkudaemon.Pool

	cfg *config.Config

	uploadsMu sync.Mutex
	uploads   map[string]int // open uploads by daemon
}

func newDaemonControlService(cfg *config.Config) *daemonControlService {
	return &daemonControlService{Pool: cfg.Pool, cfg: cfg, uploads: map[string]int{}}
}

func (s *daemonControlService) EnrollDaemon(
	ctx context.Context,
	req *nokkuv1.EnrollDaemonRequest,
) (*nokkuv1.EnrollDaemonResponse, error) {
	ci, ok := connect.CallInfoForServerContext(ctx)
	if !ok {
		return nil, errInternal
	}
	// The session is bound to the daemon's DPoP key, so a stolen token is useless without it.
	binding, err := s.enrollBinding(ctx, ci)
	if err != nil {
		return nil, err
	}

	out, err := nokkudaemon.Enroll(ctx, s.cfg.Conn, nokkudaemon.EnrollInput{
		Token:       req.GetToken(),
		Binding:     binding,
		Version:     daemonVersion(ci.RequestHeader().Get("User-Agent")),
		ReqMetadata: req.GetMetadata(),
		Connected:   s.cfg.Pool.ConnectedIn(actor.WorkspaceIDFromContext(ctx)),
		// The token must verify before anything is spent on the cap, so it is checked here instead of in the guard.
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
	token, err := s.cfg.IAM.IssueDaemonSession(ctx, out.DaemonID, binding)
	if err != nil {
		return nil, err
	}
	// The call is public, so the audit interceptor has no actor for it.
	s.cfg.Audit.Record(ctx, &audit.Event{
		Action:    "EnrollDaemon",
		ActorID:   out.DaemonID,
		ActorKind: string(actor.KindDaemon),
		ActorName: out.Name,
		Target:    out.DaemonID,
		OK:        true,
	})

	return &nokkuv1.EnrollDaemonResponse{
		Id:          &out.DaemonID,
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
	ci, ok := connect.CallInfoForServerContext(ctx)
	if !ok {
		return nil, errInternal
	}

	res, err := nokkudaemon.Sync(ctx, s.cfg.Conn, nokkudaemon.SyncInput{
		DaemonID:    actor.DaemonIDFromContext(ctx),
		Version:     daemonVersion(ci.RequestHeader().Get("User-Agent")),
		ReqMetadata: req.GetMetadata(),
		Users:       req.GetUsers(),
		PrivateIPs:  req.GetPrivateIps(),
	})
	if err != nil {
		return nil, err
	}
	return &nokkuv1.SyncDaemonResponse{
		Status:          res.Status,
		Config:          res.Config,
		Principals:      res.Principals,
		CaPublicKey:     &res.CAPublicKey,
		RetiredCaKeys:   res.RetiredCAs,
		HostCaPublicKey: &res.HostCAPublicKey,
		StateVersion:    &res.Version,
	}, nil
}

// SignHostCertificate signs the daemon's host key for its own target, under the CA that target uses.
func (s *daemonControlService) SignHostCertificate(
	ctx context.Context,
	req *nokkuv1.SignHostCertificateRequest,
) (*nokkuv1.SignHostCertificateResponse, error) {
	daemonID := actor.DaemonIDFromContext(ctx)
	var ca *db.SSHCA
	var signer gossh.Signer
	var target *db.Target
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if ca, err = q.GetCAByDaemonID(ctx, &daemonID); err != nil {
			return err
		}
		if signer, err = ssh.CASigner(ctx, q, s.cfg.Keyset, ca.ID, gossh.HostCert); err != nil {
			return err
		}
		target, err = q.GetTargetByDaemon(ctx, &daemonID)
		return err
	}); err != nil {
		return nil, err
	}
	cert, err := ssh.SignCertificate(
		ca,
		signer,
		req.GetPublicKey(),
		[]string{target.ID},
		"nokku:provision:daemon:"+daemonID,
		0,
		gossh.HostCert,
	)
	if err != nil {
		return nil, err
	}

	audit.SetTarget(ctx, ca.ID)
	audit.Set(ctx, "serial", strconv.FormatUint(cert.Serial, 10))
	audit.Set(ctx, "key_id", cert.KeyId)
	audit.Set(ctx, "principals", cert.ValidPrincipals)
	audit.Set(ctx, "expires_at", ssh.TimeFromUnix(cert.ValidBefore))
	return &nokkuv1.SignHostCertificateResponse{
		SignedCertificate: new(ssh.MarshalKey(cert)),
	}, nil
}

func (s *daemonControlService) UploadRecording(
	ctx context.Context,
	stream nokkuv1connect.DaemonControlServiceUploadRecordingServerStream,
) (*nokkuv1.UploadRecordingResponse, error) {
	daemonID := actor.DaemonIDFromContext(ctx)
	if daemonID == "" {
		return nil, newError(connect.CodePermissionDenied, "only daemons can upload recordings")
	}

	first, err := stream.Receive()
	if err != nil {
		return nil, newError(connect.CodeInvalidArgument, "missing recording metadata")
	}
	meta := first.GetMeta()
	if meta == nil || meta.GetRecordingId() == "" {
		return nil, newError(connect.CodeInvalidArgument, "missing recording metadata")
	}

	release, ok := s.takeUploadSlot(daemonID)
	if !ok {
		return nil, errTooManyUploads
	}
	defer release()

	// Asked before the row exists, so a refused upload leaves nothing behind. The daemon tries again later.
	if !s.cfg.Record.MakeRoom(ctx, actor.WorkspaceIDFromContext(ctx), meta.GetRecordingId()) {
		return nil, errRecordingStorageFull
	}
	rec, err := s.resolveUpload(ctx, daemonID, meta)
	if err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, rec.ID)
	// A daemon that dies takes ctx with it. What arrived by then is the evidence, so the writer outlives it.
	wctx, abort := context.WithCancel(context.WithoutCancel(ctx))
	defer abort()
	objectID := uuid.NewV7().String()
	w, err := s.cfg.Record.NewWriter(wctx, rec, objectID)
	if err != nil {
		return nil, fmt.Errorf("start recording %s: %w", rec.ID, err)
	}

	msgs, recvErr := receiveApart(ctx, stream)
	var size int64
	var final *nokkuv1.RecordingFinal
	// ended is the answer for an upload that was not taken whole.
	var ended error
receive:
	for final == nil {
		var msg *nokkuv1.UploadRecordingRequest
		select {
		case msg = <-msgs:
		case err := <-recvErr:
			if !errors.Is(err, io.EOF) {
				ended = newError(connect.CodeUnknown, "recording stream interrupted")
			}
			break receive
		case <-ctx.Done():
			ended = newError(connect.CodeUnavailable, "the core is shutting down, the rest goes up later")
			break receive
		}
		switch m := msg.GetMsg().(type) {
		case *nokkuv1.UploadRecordingRequest_Chunk:
			data := m.Chunk
			if len(data) == 0 {
				continue
			}
			if size+int64(len(data)) > maxUploadBytes {
				// The daemon keeps a refused file and stops sending it until its next start.
				ended = newError(connect.CodeInvalidArgument, "recording is too large, the rest is cut")
				break receive
			}
			if err := w.WriteChunk(data); err != nil {
				ended = fmt.Errorf("recording %s: %w", rec.ID, err)
				break receive
			}
			size += int64(len(data))
		case *nokkuv1.UploadRecordingRequest_Final:
			final = m.Final
		}
	}
	// Complete takes a recording nothing cut, of which every byte of the daemon's file arrived.
	complete := ended == nil && final != nil && final.GetCutReason() == "" && final.GetSizeBytes() == size
	if reason := final.GetCutReason(); reason != "" {
		audit.Set(ctx, "cut_reason", reason)
	}
	if final != nil && final.GetSizeBytes() != size {
		audit.Set(ctx, "missing_bytes", final.GetSizeBytes()-size)
	}

	// Only the last message says the session ended. Any other end of a stream is one try, the session may run on.
	var endedAt *time.Time
	if final != nil {
		endedAt = new(time.Now())
		if t := final.GetEndedAt(); t.IsValid() {
			endedAt = new(t.AsTime())
		}
	}
	if rec, err = s.storeUpload(ctx, rec, w, abort, &db.FinishRecordingUploadParams{
		ID:        rec.ID,
		ObjectID:  &objectID,
		SizeBytes: size,
		Complete:  complete,
		EndedAt:   endedAt,
	}); err != nil {
		return nil, err
	}
	if ended != nil {
		// What was stored is kept as a cut recording.
		return nil, ended
	}
	return &nokkuv1.UploadRecordingResponse{
		RecordingId: &rec.ID,
		SizeBytes:   &rec.SizeBytes,
	}, nil
}

// takeUploadSlot counts an upload against its daemon. release gives the slot back.
func (s *daemonControlService) takeUploadSlot(daemonID string) (release func(), ok bool) {
	s.uploadsMu.Lock()
	defer s.uploadsMu.Unlock()
	if s.uploads[daemonID] >= maxOpenUploads {
		return nil, false
	}
	s.uploads[daemonID]++
	return func() {
		s.uploadsMu.Lock()
		defer s.uploadsMu.Unlock()
		if s.uploads[daemonID]--; s.uploads[daemonID] == 0 {
			delete(s.uploads, daemonID)
		}
	}, true
}

// receiveApart runs Receive on its own, Receive does not watch ctx. A deploy ends ctx, and must not wait out its
// grace on a quiet stream. The handler's return closes the stream, which ends the receiving too.
func receiveApart(
	ctx context.Context,
	stream nokkuv1connect.DaemonControlServiceUploadRecordingServerStream,
) (<-chan *nokkuv1.UploadRecordingRequest, <-chan error) {
	msgs := make(chan *nokkuv1.UploadRecordingRequest)
	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case msgs <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()
	return msgs, recvErr
}

// storeUpload commits the object of this try, then keeps it under the row lock if it holds at least what is stored.
// The commit stays out of the transaction, a bucket that hangs holds neither a row nor a connection. An object that
// lost goes to the delete queue.
func (s *daemonControlService) storeUpload(
	ctx context.Context,
	opened *db.Recording,
	w *recording.Writer,
	abort func(),
	upload *db.FinishRecordingUploadParams,
) (*db.Recording, error) {
	stored := upload.SizeBytes > 0
	if !stored {
		abort()
	}
	stop := time.AfterFunc(storeTimeout, abort)
	defer stop.Stop()
	var answer error
	// Only Close cleans up after a writer, after abort it drops the object.
	if err := w.Close(); err != nil && stored {
		// Nothing of this try is stored, what an earlier one left still is.
		stored, answer = false, fmt.Errorf("commit recording %s: %w", opened.ID, err)
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	var rec *db.Recording
	err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		var kept bool
		row, err := q.LockRecording(ctx, opened.ID)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			answer = err
		case err != nil:
			return err
		case !bytes.Equal(row.Key, opened.Key):
			// Deleted and made again, or a rotation resealed the key. The daemon sends the file again either way.
			answer = pgx.ErrNoRows
		case row.Complete:
			rec, answer = row, errRecordingFinalized
		default:
			kept = stored && upload.SizeBytes >= row.SizeBytes
			// An earlier try stored more, or this one nothing. The larger copy wins, a shorter one that calls itself
			// whole too.
			next := &db.FinishRecordingUploadParams{ID: row.ID, SizeBytes: row.SizeBytes, EndedAt: upload.EndedAt}
			if kept {
				next = upload
			}
			if rec, err = q.FinishRecordingUpload(ctx, next); err != nil {
				return err
			}
		}
		if stored && !kept {
			return q.QueueLostRecordingObject(ctx, *upload.ObjectID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rec, answer
}

// resolveUpload resumes the recording when the daemon uploads its id again.
func (s *daemonControlService) resolveUpload(
	ctx context.Context,
	daemonID string,
	rm *nokkuv1.RecordingMeta,
) (*db.Recording, error) {
	// The id is sealed into the recording's key. Postgres would hand back another spelling than a capital one.
	if !login.ValidID(rm.GetRecordingId()) {
		return nil, newError(connect.CodeInvalidArgument, "the recording id must be a lowercase UUID")
	}
	var rec *db.Recording
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		existing, err := q.GetRecording(ctx, rm.GetRecordingId())
		if err == nil {
			if existing.DaemonID == nil || *existing.DaemonID != daemonID {
				// Refused, not AlreadyExists, so the daemon keeps its file and nobody can get another server's deleted.
				return newError(connect.CodeInvalidArgument, "recording belongs to another daemon")
			}
			if existing.Complete {
				return errRecordingFinalized
			}
			rec = existing
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var startedAt *time.Time
		if t := rm.GetStartedAt(); t.IsValid() {
			startedAt = new(t.AsTime())
		}
		// The reported principal must name this daemon's target and the session's account, or the recording is misfiled.
		var subjectID *string
		if rm.GetPrincipal() != "" {
			target, err := q.GetTargetByDaemon(ctx, &daemonID)
			if err != nil {
				return err
			}
			p, ok := login.ParsePrincipal(rm.GetPrincipal())
			if !ok || p.TargetID != target.ID || p.Username != rm.GetUsername() {
				return newError(connect.CodeInvalidArgument, "the principal does not match the session")
			}
			subjectID = &p.SubjectID
		}
		aad := recording.KeyAAD(actor.WorkspaceIDFromContext(ctx), rm.GetRecordingId())
		key, err := s.cfg.Keyset.Seal(aad, recording.NewKey())
		if err != nil {
			return err
		}
		rec, err = q.CreateRecording(ctx, &db.CreateRecordingParams{
			ID:        rm.GetRecordingId(),
			DaemonID:  daemonID,
			Username:  rm.GetUsername(),
			SubjectID: subjectID,
			Principal: rm.GetPrincipal(),
			Key:       key,
			StartedAt: startedAt,
		})
		if db.IsUniqueViolation(err) {
			// Another upload of this id made the row first. AlreadyExists would tell the daemon to delete its file.
			return newError(connect.CodeAborted, "another upload of this recording just started, try again")
		}
		return err
	}); err != nil {
		return nil, err
	}
	return rec, nil
}

// UnenrollDaemon removes the calling daemon and the session it called with.
func (s *daemonControlService) UnenrollDaemon(
	ctx context.Context,
	_ *nokkuv1.UnenrollDaemonRequest,
) (*nokkuv1.UnenrollDaemonResponse, error) {
	daemonID := actor.DaemonIDFromContext(ctx)
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		if _, err := q.DeleteDaemon(ctx, daemonID); err != nil {
			return err
		}
		_, err := q.DeleteSubjectTokens(ctx, daemonID)
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.UnenrollDaemonResponse{}, nil
}

// enrollBinding returns the DPoP key thumbprint. A missing proof is an error, daemons must enroll key-bound.
func (s *daemonControlService) enrollBinding(ctx context.Context, ci *connect.CallInfo) (string, error) {
	svc := s.cfg.IAM
	if svc.DPoP == nil {
		return "", newError(connect.CodeUnimplemented, "DPoP is not configured")
	}

	ws, _ := actor.WorkspaceFromContext(ctx)
	meta, _ := actor.RequestMetaFromContext(ctx)
	proof, err := dpop.ProofFrom(meta.Header)
	if err != nil {
		return "", newError(connect.CodeInvalidArgument, "invalid DPoP proof")
	}
	binding, err := svc.DPoP.Verify(
		proof,
		"",
		http.MethodPost,
		ws.BaseURL+nokkuv1connect.DaemonControlServiceEnrollDaemonProcedure,
		"",
	)
	if err != nil {
		if errors.Is(err, dpop.ErrNonce) {
			svc.AdvertiseDPoPNonce(ctx, ci.ResponseHeader())
			return "", newError(connect.CodeUnauthenticated, "stale DPoP nonce")
		}
		if !iam.IsCredentialError(err) {
			return "", err
		}
		return "", newError(connect.CodeInvalidArgument, "invalid DPoP proof")
	}
	return binding, nil
}

// daemonVersion takes the version out of nokkud's user agent, "nokkud/<version> (<os>/<arch>)". Any other agent,
// or a version too long to be one, gives none.
func daemonVersion(userAgent string) string {
	rest, ok := strings.CutPrefix(userAgent, "nokkud/")
	if !ok {
		return ""
	}
	version, _, _ := strings.Cut(rest, " ")
	if len(version) > 64 {
		return ""
	}
	return version
}
