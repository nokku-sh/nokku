package api

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLimitBodyCutsStalledBody(t *testing.T) {
	t.Parallel()
	readErr := make(chan error, 1)
	srv := httptest.NewServer(limitBody(1<<10, 100*time.Millisecond)(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, err := io.ReadAll(r.Body)
			readErr <- err
		}),
	))
	t.Cleanup(srv.Close)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = conn.Write([]byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\npartial"))
	require.NoError(t, err)

	select {
	case err := <-readErr:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded, "a stalled body must fail on the deadline")
	case <-time.After(5 * time.Second):
		t.Fatal("the handler still waits on a stalled body")
	}
}

func TestLimitBodyLeavesSlowHandlerAlone(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(limitBody(1<<10, 50*time.Millisecond)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			select {
			case <-r.Context().Done():
				w.WriteHeader(http.StatusServiceUnavailable)
			case <-time.After(300 * time.Millisecond):
				w.WriteHeader(http.StatusNoContent)
			}
		}),
	))
	t.Cleanup(srv.Close)

	for _, body := range []string{"", "a=b"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL, strings.NewReader(body))
		require.NoError(t, err)
		res, err := srv.Client().Do(req)
		require.NoError(t, err)
		_ = res.Body.Close()
		assert.Equal(t, http.StatusNoContent, res.StatusCode, "body %q, the deadline must end with the body", body)
	}
}
