package client

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type closeTrackingBody struct {
	io.Reader

	closed bool
}

type fixedRoundTripper struct{ body *closeTrackingBody }

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

func (f fixedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       f.body,
		Request:    req,
	}, nil
}

func TestDeviceTransportClosesUpstreamBody(t *testing.T) {
	body := &closeTrackingBody{Reader: strings.NewReader(`{"ok":true}`)}
	tr := &deviceTransport{next: fixedRoundTripper{body: body}}
	req, err := http.NewRequest(http.MethodPost, "https://example.test/auth/device/token", strings.NewReader("x"))
	require.NoError(t, err)

	_, err = tr.RoundTrip(req)
	require.NoError(t, err)
	assert.True(t, body.closed, "upstream response body was not closed")
}
