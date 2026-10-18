package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

const (
	streamTick    = 5 * time.Second
	streamBatch   = 500
	streamTimeout = 10 * time.Second
	// streamRetry is the wait after a failed delivery. The cursor stays, so nothing is lost meanwhile.
	streamRetry = time.Minute
)

// Stream kinds, the same as the audit_streams CHECK.
const (
	StreamWebhook = "webhook"
	StreamSplunk  = "splunk"
	StreamDatadog = "datadog"
)

// streamLoop sends new events to every enabled stream until ctx ends.
func (s *Service) streamLoop(ctx context.Context) {
	ticker := time.NewTicker(streamTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		streams, err := s.conn.Sys().ListDueAuditStreams(ctx)
		if err != nil {
			slog.Warn("audit streams not read", "error", err)
			continue
		}
		// One plan lookup per workspace and tick. A lapsed plan keeps its streams, they wait until it comes back.
		allowed := make(map[string]bool)
		for _, st := range streams {
			ok, seen := allowed[st.WorkspaceID]
			if !seen {
				ok = s.entitlements.Resolve(ctx, st.WorkspaceID).Has(entitlement.FeatureAuditStreaming)
				allowed[st.WorkspaceID] = ok
			}
			if ok {
				s.deliver(ctx, st)
			}
		}
	}
}

// deliver sends what is new and records how it went.
func (s *Service) deliver(ctx context.Context, st *db.AuditStream) {
	err := s.sendNew(ctx, st)
	switch {
	case err == nil && st.FailingSince != nil:
		if err := s.conn.Sys().ClearAuditStreamFailure(ctx, st.ID); err != nil {
			slog.Warn("audit stream recovery not recorded", "error", err, "stream_id", st.ID)
		}
	case err != nil:
		slog.Warn("audit stream delivery failed", "error", err, "stream_id", st.ID, "workspace_id", st.WorkspaceID)
		if err := s.conn.Sys().FailAuditStream(ctx, &db.FailAuditStreamParams{
			ID:        st.ID,
			LastError: err.Error(),
			Wait:      streamRetry,
		}); err != nil {
			slog.Warn("audit stream failure not recorded", "error", err, "stream_id", st.ID)
		}
	}
}

// sendNew sends in batches until the stream caught up or a send fails. Nothing is held open during a send. The
// cursor moves only from where its batch was read, so a stream never skips what it did not send.
func (s *Service) sendNew(ctx context.Context, st *db.AuditStream) error {
	for {
		rows, err := s.conn.Sys().ListAuditLogsAfter(ctx, &db.ListAuditLogsAfterParams{
			WorkspaceID: st.WorkspaceID,
			CursorTs:    st.CursorTs,
			CursorID:    st.CursorID,
			MaxRows:     streamBatch,
		})
		if err != nil || len(rows) == 0 {
			return err
		}
		events := make([]*Event, len(rows))
		for i, r := range rows {
			events[i] = eventFromRow(r)
		}
		if err := s.send(ctx, st, events); err != nil {
			return err
		}
		last := events[len(events)-1]
		if err := s.conn.Sys().AdvanceAuditStream(ctx, &db.AdvanceAuditStreamParams{
			ID:       st.ID,
			CursorTs: last.Timestamp,
			CursorID: last.ID,
			FromTs:   st.CursorTs,
			FromID:   st.CursorID,
		}); err != nil {
			return err
		}
		st.CursorTs, st.CursorID = last.Timestamp, last.ID
		if len(rows) < streamBatch {
			return nil
		}
	}
}

// TestStream sends one made up event, so an admin sees at once whether the destination takes it.
func (s *Service) TestStream(ctx context.Context, st *db.AuditStream) error {
	return s.send(ctx, st, []*Event{{
		ID:          "00000000-0000-0000-0000-000000000000",
		Timestamp:   time.Now().UTC(),
		WorkspaceID: st.WorkspaceID,
		Action:      "StreamTest",
		OK:          true,
	}})
}

func (s *Service) send(ctx context.Context, st *db.AuditStream, events []*Event) error {
	body, err := streamBody(st.Kind, events)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, st.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nokku-audit-stream")
	secret := string(st.Secret)
	switch st.Kind {
	case StreamWebhook:
		stamp := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set("X-Nokku-Timestamp", stamp)
		req.Header.Set("X-Nokku-Signature", "sha256="+Sign(secret, stamp, body))
	case StreamSplunk:
		req.Header.Set("Authorization", "Splunk "+secret)
	case StreamDatadog:
		req.Header.Set("Dd-Api-Key", secret)
	}

	res, err := s.egress.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		detail, _ := io.ReadAll(io.LimitReader(res.Body, 200))
		return fmt.Errorf("the destination answered %s: %s", res.Status, bytes.TrimSpace(detail))
	}
	return nil
}

// refuseRedirect keeps the API key or the signature from going to a host nobody chose.
func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Sign is the webhook signature, an HMAC-SHA256 over the timestamp, a dot and the body. Receivers check it so
// nobody else can post events, and reject an old timestamp so a captured request is not replayed.
func Sign(secret, stamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stamp + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// streamBody shapes a batch the way each destination reads it. Every event keeps its id, so a receiver drops what
// a retry sends twice.
func streamBody(kind string, events []*Event) ([]byte, error) {
	switch kind {
	case StreamWebhook:
		return json.Marshal(events)
	case StreamSplunk:
		// HEC takes events one after another, not as an array.
		var buf bytes.Buffer
		for _, e := range events {
			line, err := json.Marshal(map[string]any{
				"time":       float64(e.Timestamp.UnixMilli()) / 1000,
				"source":     "nokku",
				"sourcetype": "nokku:audit",
				"event":      e,
			})
			if err != nil {
				return nil, err
			}
			buf.Write(line)
		}
		return buf.Bytes(), nil
	case StreamDatadog:
		logs := make([]map[string]any, len(events))
		for i, e := range events {
			logs[i] = map[string]any{
				"ddsource": "nokku",
				"service":  "nokku",
				"message":  strings.TrimSpace(e.Action + " " + e.Target),
				"nokku":    e,
			}
		}
		return json.Marshal(logs)
	}
	return nil, errors.New("unknown stream kind " + kind)
}

func eventFromRow(r *db.AuditAuditLog) *Event {
	var details map[string]any
	_ = json.Unmarshal(r.Details, &details)
	return &Event{
		ID:          r.ID,
		Timestamp:   r.Timestamp,
		WorkspaceID: r.WorkspaceID,
		ActorID:     r.ActorID,
		ActorKind:   r.ActorKind,
		ActorName:   r.ActorName,
		Action:      r.Action,
		Target:      r.Target,
		OK:          r.Ok,
		IP:          r.Ip,
		UserAgent:   r.UserAgent,
		Details:     details,
	}
}
