package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/egress"
	"github.com/nokku-sh/nokku/internal/entitlement"
)

const (
	streamQueueSize     = 1024
	streamWorkers       = 2
	streamAttempts      = 5 // first try included
	streamTimeout       = 10 * time.Second
	streamRefreshPeriod = 30 * time.Second
)

// webhookSink drops events on a full queue, a slow destination must not stall a login or grow memory.
type webhookSink struct {
	conn         *db.Connection
	entitlements *entitlement.Service
	client       *http.Client
	queue        chan *Event
	// destinations is refreshed periodically so events cost no queries.
	destinations atomic.Pointer[map[string]destination]
	// backoff is a field so tests don't wait seconds.
	backoff time.Duration
	dropped atomic.Uint64
}

type destination struct {
	url    string
	secret string
}

var _ sink = (*webhookSink)(nil)

// newWebhookSink guards against private destinations, see egress.NewClient.
func newWebhookSink(
	ctx context.Context,
	conn *db.Connection,
	entitlements *entitlement.Service,
) (*webhookSink, error) {
	client, err := egress.NewClient(streamTimeout)
	if err != nil {
		return nil, err
	}
	s := &webhookSink{
		conn:         conn,
		entitlements: entitlements,
		client:       client,
		queue:        make(chan *Event, streamQueueSize),
		backoff:      time.Second,
	}
	empty := map[string]destination{}
	s.destinations.Store(&empty)
	s.refresh(ctx)

	for range streamWorkers {
		go s.work(ctx)
	}
	go s.refreshLoop(ctx)
	return s, nil
}

// Append never blocks or fails the caller.
func (s *webhookSink) Append(_ context.Context, event *Event) error {
	if event == nil || event.WorkspaceID == "" {
		return nil
	}
	select {
	case s.queue <- event:
	default:
		// Log the first drop and every hundredth so a dead destination can't fill the log.
		if n := s.dropped.Add(1); n == 1 || n%100 == 0 {
			slog.Warn("audit webhook queue full, dropping events",
				"workspace_id", event.WorkspaceID, "dropped", n)
		}
	}
	return nil
}

func (s *webhookSink) work(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.queue:
			s.deliver(ctx, event)
		}
	}
}

// deliver drops what it cannot deliver, Postgres holds the record anyway.
func (s *webhookSink) deliver(ctx context.Context, event *Event) {
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

// post only retries network errors, 408, 429 and 5xx. Any other 4xx would fail the same way again.
func (s *webhookSink) post(ctx context.Context, dest destination, body []byte) (bool, error) {
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
	retry := resp.StatusCode >= 500 || resp.StatusCode == http.StatusRequestTimeout ||
		resp.StatusCode == http.StatusTooManyRequests
	return retry, &httpError{status: resp.StatusCode}
}

func (s *webhookSink) destination(workspaceID string) destination {
	if m := s.destinations.Load(); m != nil {
		return (*m)[workspaceID]
	}
	return destination{}
}

func (s *webhookSink) refreshLoop(ctx context.Context) {
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

// refresh keeps the previous destinations on failure, so a database blip cannot stop streaming.
func (s *webhookSink) refresh(ctx context.Context) {
	next := map[string]destination{}
	err := s.conn.SysTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListWorkspaceAuditWebhooks(ctx)
		if err != nil {
			return err
		}
		for _, row := range rows {
			// A downgraded workspace keeps its setting but stops streaming.
			if !s.entitlements.Has(ctx, row.ID, entitlement.FeatureAuditStreaming) {
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

// sign covers the timestamp, so a captured request cannot be replayed with a fresh one.
func sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func validWebhookURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("destination URL scheme must be http or https")
	}
	if parsed.Host == "" {
		return "", errors.New("destination URL has no host")
	}
	return parsed.String(), nil
}

type httpError struct{ status int }

func (e *httpError) Error() string {
	return "destination returned HTTP " + http.StatusText(e.status)
}
