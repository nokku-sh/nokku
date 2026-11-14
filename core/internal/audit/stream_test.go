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

	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
)

func TestSignIsTheDocumentedHMAC(t *testing.T) {
	// echo -n '1700000000.{}' | openssl dgst -sha256 -hmac secret
	assert.Equal(t, "b8569b78799ff9e3cbff0fc2d63a33a2b57f3282abd07c37ae5e8e7d79a5f163",
		sign("secret", "1700000000", []byte("{}")))
	assert.NotEqual(t, sign("secret", "1700000000", []byte("{}")), sign("secret", "1700000001", []byte("{}")),
		"the timestamp must be signed, or an old request replays")
	assert.NotEqual(t, sign("secret", "1", []byte("{}")), sign("other", "1", []byte("{}")))
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
	assert.InDelta(t, 1792324800500, got[0]["timestamp"], 0.5, "the event's own time, in milliseconds at the top")
}

func TestSendSetsEachDestinationsAuth(t *testing.T) {
	tests := []struct {
		kind   string
		header string
		want   func(r *http.Request, body []byte) string
	}{
		{StreamWebhook, "X-Nokku-Signature", func(r *http.Request, body []byte) string {
			return "sha256=" + sign("s3cret-key", r.Header.Get("X-Nokku-Timestamp"), body)
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
			sut := &Service{egress: srv.Client(), keys: testKeys(t)}

			err := sut.send(t.Context(), testStream(t, sut, tt.kind, srv.URL, "s3cret-key"), testEvents())

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
	sut := &Service{egress: client, keys: testKeys(t)}

	err := sut.send(t.Context(), testStream(t, sut, StreamDatadog, srv.URL, "key"), testEvents())

	require.ErrorContains(t, err, "302", "a redirect must fail the delivery, not follow it with the key")
}

func testKeys(t *testing.T) *kms.Keyset {
	t.Helper()
	keys, err := kms.Ephemeral()
	require.NoError(t, err)
	return keys
}

// testStream seals secret the way CreateAuditStream stores it.
func testStream(t *testing.T, s *Service, kind, url, secret string) *db.AuditStream {
	t.Helper()
	st := &db.AuditStream{ID: "s1", WorkspaceID: "w1", Kind: kind, URL: url}
	sealed, err := s.keys.Seal(SecretAAD(st.WorkspaceID, st.ID), []byte(secret))
	require.NoError(t, err)
	st.Secret = sealed
	return st
}
