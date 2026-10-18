package audit

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/db"
)

func TestSignIsTheDocumentedHMAC(t *testing.T) {
	// echo -n '1700000000.{}' | openssl dgst -sha256 -hmac secret, what a receiver computes.
	assert.Equal(t, "b8569b78799ff9e3cbff0fc2d63a33a2b57f3282abd07c37ae5e8e7d79a5f163",
		Sign("secret", "1700000000", []byte("{}")))
	assert.NotEqual(t, Sign("secret", "1700000000", []byte("{}")), Sign("secret", "1700000001", []byte("{}")),
		"the timestamp must be signed, or an old request replays")
	assert.NotEqual(t, Sign("secret", "1", []byte("{}")), Sign("other", "1", []byte("{}")))
}

func testEvents() []*Event {
	at := time.Date(2026, 10, 18, 12, 0, 0, 500_000_000, time.UTC)
	return []*Event{
		{ID: "e1", Timestamp: at, Action: "Login", OK: true},
		{ID: "e2", Timestamp: at, Action: "DeleteTarget", Target: "t1", OK: true},
	}
}

func TestStreamBodyWebhookIsTheExportShape(t *testing.T) {
	body, err := streamBody(StreamWebhook, testEvents())
	require.NoError(t, err)

	var got []map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	require.Len(t, got, 2)
	assert.Equal(t, "e1", got[0]["id"], "every event keeps its id for dedup")
	assert.Equal(t, "Login", got[0]["action"])
}

func TestStreamBodySplunkIsOneEventAfterAnother(t *testing.T) {
	body, err := streamBody(StreamSplunk, testEvents())
	require.NoError(t, err)

	dec := jsontext.NewDecoder(bytes.NewReader(body))
	var events []map[string]any
	for {
		var e map[string]any
		err := json.UnmarshalDecode(dec, &e)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		events = append(events, e)
	}
	require.Len(t, events, 2, "HEC takes concatenated events, not an array")
	assert.Equal(t, "nokku:audit", events[0]["sourcetype"])
	assert.InDelta(t, 1792324800.5, events[0]["time"], 0.001, "seconds with the fraction")
}

func TestStreamBodyDatadogNamesItsSource(t *testing.T) {
	body, err := streamBody(StreamDatadog, testEvents())
	require.NoError(t, err)

	var got []map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "nokku", got[0]["ddsource"])
	assert.Equal(t, "Login", got[0]["message"], "no trailing space without a target")
	assert.Equal(t, "DeleteTarget t1", got[1]["message"])
}

func TestSendSetsEachDestinationsAuth(t *testing.T) {
	tests := []struct {
		kind   string
		header string
		want   func(r *http.Request, body []byte) string
	}{
		{StreamWebhook, "X-Nokku-Signature", func(r *http.Request, body []byte) string {
			return "sha256=" + Sign("s3cret-key", r.Header.Get("X-Nokku-Timestamp"), body)
		}},
		{StreamSplunk, "Authorization", func(*http.Request, []byte) string { return "Splunk s3cret-key" }},
		{StreamDatadog, "DD-API-KEY", func(*http.Request, []byte) string { return "s3cret-key" }},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			var got, want string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				got, want = r.Header.Get(tt.header), tt.want(r, body)
			}))
			t.Cleanup(srv.Close)
			sut := &Service{egress: srv.Client()}

			err := sut.send(t.Context(), &db.AuditStream{Kind: tt.kind, URL: srv.URL, Secret: []byte("s3cret-key")},
				testEvents())

			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestSendRefusesARedirect(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.test/", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.CheckRedirect = refuseRedirect
	sut := &Service{egress: client}

	err := sut.send(
		t.Context(),
		&db.AuditStream{Kind: StreamDatadog, URL: srv.URL, Secret: []byte("key")},
		testEvents(),
	)

	require.ErrorContains(t, err, "302", "a redirect must fail the delivery, not follow it with the key")
}
