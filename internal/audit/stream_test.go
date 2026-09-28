package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// newTestSink builds a sink with fixed destinations and no database or
// refresher, so delivery behaviour can be tested on its own.
func newTestSink(destinations map[string]destination) *WebhookSink {
	s := &WebhookSink{
		client:  &http.Client{Timeout: 5 * time.Second},
		queue:   make(chan *Event, streamQueueSize),
		backoff: time.Millisecond,
	}
	s.destinations.Store(&destinations)
	return s
}

type recorder struct {
	mu       sync.Mutex
	bodies   [][]byte
	attempts int
}

func (r *recorder) add(body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bodies = append(r.bodies, body)
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

func (r *recorder) attempt() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts++
	return r.attempts
}

func TestWebhookSink_DeliverRoutesByWorkspace(t *testing.T) {
	var got recorder
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.add(body)
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
	}))
	defer server.Close()

	sink := newTestSink(map[string]destination{"ws-1": {url: server.URL}})
	ctx := context.Background()

	sink.deliver(ctx, &Event{WorkspaceID: "ws-1", Action: "CreateTarget"})
	// No destination for this workspace: nothing is sent, nothing panics.
	sink.deliver(ctx, &Event{WorkspaceID: "ws-2", Action: "CreateTarget"})
	// Global events carry no workspace and have no destination.
	sink.deliver(ctx, &Event{Action: "Login"})

	if got.count() != 1 {
		t.Fatalf("delivered %d events, want 1", got.count())
	}
	var event Event
	if err := json.Unmarshal(got.bodies[0], &event); err != nil {
		t.Fatalf("destination received invalid JSON: %v", err)
	}
	if event.WorkspaceID != "ws-1" || event.Action != "CreateTarget" {
		t.Errorf("delivered %+v, want ws-1/CreateTarget", event)
	}
}

func TestWebhookSink_RetriesTransientFailure(t *testing.T) {
	var got recorder
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if got.attempt() < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink := newTestSink(map[string]destination{"ws-1": {url: server.URL}})
	sink.deliver(context.Background(), &Event{WorkspaceID: "ws-1", Action: "CreateTarget"})

	if got.attempts != 3 {
		t.Errorf("attempts = %d, want 3 (two failures then success)", got.attempts)
	}
}

func TestWebhookSink_DoesNotRetryRejectedEvent(t *testing.T) {
	var got recorder
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		got.attempt()
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	sink := newTestSink(map[string]destination{"ws-1": {url: server.URL}})
	sink.deliver(context.Background(), &Event{WorkspaceID: "ws-1", Action: "CreateTarget"})

	if got.attempts != 1 {
		t.Errorf("attempts = %d, want 1: a 4xx is not retryable", got.attempts)
	}
}

func TestWebhookSink_AppendNeverBlocks(t *testing.T) {
	sink := newTestSink(map[string]destination{"ws-1": {url: "http://127.0.0.1:1/audit"}})
	sink.queue = make(chan *Event, 1)
	sink.queue <- &Event{WorkspaceID: "ws-1"} // fill the queue

	done := make(chan error, 1)
	go func() {
		done <- sink.Append(context.Background(), &Event{WorkspaceID: "ws-1", Action: "CreateTarget"})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Append returned %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Append blocked on a full queue")
	}
	if sink.dropped.Load() != 1 {
		t.Errorf("dropped = %d, want 1", sink.dropped.Load())
	}
}

func TestValidWebhookURL(t *testing.T) {
	for _, raw := range []string{"https://example.com/audit", "http://127.0.0.1:8080/hook"} {
		if _, err := validWebhookURL(raw); err != nil {
			t.Errorf("validWebhookURL(%q) = %v, want accepted", raw, err)
		}
	}
	for _, raw := range []string{"", "example.com", "ftp://example.com", "file:///etc/passwd"} {
		if _, err := validWebhookURL(raw); err == nil {
			t.Errorf("validWebhookURL(%q) accepted, want rejected", raw)
		}
	}
}

func TestWebhookSink_SignsPayloadWhenSecretIsSet(t *testing.T) {
	const secret = "s3cret-value"
	type signed struct {
		timestamp string
		signature string
		body      []byte
	}
	got := make(chan signed, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- signed{
			timestamp: r.Header.Get("X-Nokku-Timestamp"),
			signature: r.Header.Get("X-Nokku-Signature"),
			body:      body,
		}
	}))
	defer server.Close()

	sink := newTestSink(map[string]destination{"ws-1": {url: server.URL, secret: secret}})
	sink.deliver(context.Background(), &Event{WorkspaceID: "ws-1", Action: "CreateTarget"})

	select {
	case received := <-got:
		if received.timestamp == "" {
			t.Fatal("no X-Nokku-Timestamp header")
		}
		if _, err := strconv.ParseInt(received.timestamp, 10, 64); err != nil {
			t.Errorf("X-Nokku-Timestamp = %q, want unix seconds", received.timestamp)
		}
		want := "sha256=" + sign(secret, received.timestamp, received.body)
		if received.signature != want {
			t.Errorf("X-Nokku-Signature = %q, want %q", received.signature, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("destination received nothing")
	}
}

func TestWebhookSink_UnsignedWithoutSecret(t *testing.T) {
	headers := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
	}))
	defer server.Close()

	sink := newTestSink(map[string]destination{"ws-1": {url: server.URL}})
	sink.deliver(context.Background(), &Event{WorkspaceID: "ws-1", Action: "CreateTarget"})

	select {
	case header := <-headers:
		if header.Get("X-Nokku-Signature") != "" {
			t.Errorf("signed without a secret: %q", header.Get("X-Nokku-Signature"))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("destination received nothing")
	}
}

func TestService_AppendFansOutToEverySink(t *testing.T) {
	first := &stubSink{}
	failing := &stubSink{err: errors.New("destination down")}
	service := &Service{sinks: []Sink{first, failing}}

	err := service.Append(context.Background(), &Event{Action: "CreateTarget"})
	if err == nil {
		t.Fatal("Append returned nil, want the failing sink reported")
	}
	if len(first.events) != 1 {
		t.Errorf("first sink got %d events, want 1: one bad sink must not stop the others",
			len(first.events))
	}
}

type stubSink struct {
	events []*Event
	err    error
}

func (s *stubSink) Append(_ context.Context, event *Event) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, event)
	return nil
}
