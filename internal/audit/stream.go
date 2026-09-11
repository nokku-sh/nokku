package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
)

const (
	// streamQueueSize bounds how far a destination can fall behind before
	// events are dropped. A full queue never blocks the caller.
	streamQueueSize = 1024
	streamWorkers   = 2
	// streamAttempts counts the first try plus retries. Only network errors,
	// 429, and 5xx are retried: a 4xx is the destination rejecting the event,
	// so retrying it would just repeat the same failure.
	streamAttempts      = 5
	streamTimeout       = 10 * time.Second
	streamRefreshPeriod = 30 * time.Second
)

// WebhookSink streams every audit event to the destination configured on its
// workspace, as one JSON object per POST. It is the second Sink.
//
// It never fails the caller. Append hands the event to a bounded queue and
// returns. Delivery, retry, and backoff happen on the workers. A full queue
// drops the event and counts it, because a slow destination must not stall a
// login or grow memory without bound.
//
// A destination is a URL plus an optional secret. With a secret set, each
// request carries a timestamp and an HMAC-SHA256 signature over
// timestamp.body, so the receiver can prove the event came from Nokku and
// reject replays.
//
// Two rules keep it honest: only workspaces on a plan with the streaming
// feature are streamed, and events with no workspace are not streamed at all,
// since the destination belongs to a workspace and there is nothing to route
// them to.
type WebhookSink struct {
	conn         *db.Connection
	entitlements *entitlement.Service
	client       *http.Client
	queue        chan *Event
	// destinations maps workspace id to destination. Refreshed periodically
	// rather than read per event, so a busy workspace costs no queries.
	destinations atomic.Pointer[map[string]destination]
	// backoff is the first retry delay, doubled per attempt. A field so tests
	// do not have to wait seconds.
	backoff time.Duration
	dropped atomic.Uint64
}

type destination struct {
	url    string
	secret string
}

var _ Sink = (*WebhookSink)(nil)

// NewWebhookSink loads the configured destinations and starts the refresher
// and delivery workers. They stop with ctx.
func NewWebhookSink(
	ctx context.Context,
	conn *db.Connection,
	entitlements *entitlement.Service,
) *WebhookSink {
	s := &WebhookSink{
		conn:         conn,
		entitlements: entitlements,
		client:       &http.Client{Timeout: streamTimeout},
		queue:        make(chan *Event, streamQueueSize),
		backoff:      time.Second,
	}
	empty := map[string]destination{}
	s.destinations.Store(&empty)
	// Load once before returning so an event written immediately after boot
	// still finds its destination.
	s.refresh(ctx)

	for range streamWorkers {
		go s.work(ctx)
	}
	go s.refreshLoop(ctx)
	return s
}

// Append enqueues an event for delivery. It never blocks and never returns an
// error: the sink's job is to stay out of the caller's way.
func (s *WebhookSink) Append(_ context.Context, event *Event) error {
	if event == nil || event.WorkspaceID == "" {
		return nil
	}
	select {
	case s.queue <- event:
	default:
		// Log the first drop and then every hundredth, so a destination that
		// is down cannot fill the log while still being visible.
		if n := s.dropped.Add(1); n == 1 || n%100 == 0 {
			slog.Warn("audit webhook queue full, dropping events",
				"workspace_id", event.WorkspaceID, "dropped", n)
		}
	}
	return nil
}

// work delivers queued events until ctx ends.
func (s *WebhookSink) work(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.queue:
			s.deliver(ctx, event)
		}
	}
}

// deliver posts one event, retrying transient failures with exponential
// backoff. Anything it cannot deliver is logged and dropped: an audit event
// lives in Postgres regardless, so the stream is a copy, not the record.
func (s *WebhookSink) deliver(ctx context.Context, event *Event) {
	dest := s.destination(event.WorkspaceID)
	if dest.url == "" {
		return
	}

	body, err := json.Marshal(event)
	if err != nil {
		slog.Warn("audit webhook could not encode event", "error", err)
		return
	}

	delay := s.backoff
	for attempt := 1; ; attempt++ {
		retry, err := s.post(ctx, dest, body)
		if err == nil {
			return
		}
		if !retry {
			slog.Warn("audit webhook rejected the event",
				"workspace_id", event.WorkspaceID, "action", event.Action, "error", err)
			return
		}
		if attempt >= streamAttempts {
			slog.Warn("audit webhook delivery failed",
				"workspace_id", event.WorkspaceID, "action", event.Action,
				"attempts", attempt, "error", err)
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// post sends one request. It reports whether a failed attempt is worth
// retrying, and the failure.
func (s *WebhookSink) post(ctx context.Context, dest destination, body []byte) (bool, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, dest.url, bytes.NewReader(body),
	)
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nokku-audit-webhook")

	if dest.secret != "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set("X-Nokku-Timestamp", timestamp)
		req.Header.Set("X-Nokku-Signature", "sha256="+sign(dest.secret, timestamp, body))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return true, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	// 408 and 429 are the two 4xx that mean "try again", not "go away".
	retry := resp.StatusCode >= 500 || resp.StatusCode == http.StatusRequestTimeout ||
		resp.StatusCode == http.StatusTooManyRequests
	return retry, &httpError{status: resp.StatusCode}
}

// destination returns the destination configured for a workspace, or the zero
// value.
func (s *WebhookSink) destination(workspaceID string) destination {
	if m := s.destinations.Load(); m != nil {
		return (*m)[workspaceID]
	}
	return destination{}
}

// refreshLoop reloads destinations so a settings change takes effect without a
// restart. One query per period, whatever the event rate.
func (s *WebhookSink) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(streamRefreshPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refresh(ctx)
		}
	}
}

// refresh reads every configured destination. It runs as nokku_system: the
// workspaces table is RLS-scoped to a single tenant and this is the
// cross-tenant read. A failure keeps the previous destinations, so a database
// blip cannot silently stop streaming.
func (s *WebhookSink) refresh(ctx context.Context) {
	next := map[string]destination{}
	err := s.conn.WithTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListWorkspaceAuditWebhooks(ctx)
		if err != nil {
			return err
		}
		for _, row := range rows {
			// A workspace that downgrades stops streaming even though the
			// destination stays configured, matching what the guard does to
			// the setting itself.
			if !s.entitlements.Has(ctx, row.ID, entitlement.FeatureAuditStreaming) {
				slog.Debug("audit webhook destination not streamed, plan lacks the feature",
					"workspace_id", row.ID)
				continue
			}
			url, err := validWebhookURL(row.WebhookURL)
			if err != nil {
				slog.Warn("audit webhook destination ignored",
					"workspace_id", row.ID, "error", err)
				continue
			}
			next[row.ID] = destination{url: url, secret: row.WebhookSecret}
		}
		return nil
	})
	if err != nil {
		slog.Warn("audit webhook destinations not refreshed", "error", err)
		return
	}
	s.destinations.Store(&next)
}

// sign authenticates one request. The timestamp is inside the signature, so a
// captured request cannot be replayed with a fresh one.
func sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// validWebhookURL accepts only http and https destinations.
func validWebhookURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", &urlError{scheme: parsed.Scheme}
	}
	if parsed.Host == "" {
		return "", &urlError{scheme: parsed.Scheme}
	}
	return parsed.String(), nil
}

type httpError struct{ status int }

func (e *httpError) Error() string {
	return "destination returned HTTP " + http.StatusText(e.status)
}

type urlError struct{ scheme string }

func (e *urlError) Error() string {
	if e.scheme == "" {
		return "destination URL has no scheme or host"
	}
	return "destination URL scheme " + e.scheme + " is not http or https"
}
