package api

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/config"
)

// Unset, any peer on a private network could name the client address that
// source-address limits are checked against.
func TestHostedServiceNeedsTrustedProxies(t *testing.T) {
	cfg := &config.Config{}
	cfg.SaaS = true
	require.ErrorContains(t, New(cfg).Start(t.Context()), "NOKKU_TRUSTED_PROXIES")
	cfg.TrustedProxies = []string{" "}
	assert.ErrorContains(t, New(cfg).Start(t.Context()), "NOKKU_TRUSTED_PROXIES", "a blank entry names no proxy")
}

// A proxy without h2c is the likeliest setup mistake, and a bare 505 from
// connect names no fix. nokkud and nk print what the core answers.
func TestDuplexStreamOverHTTP1NamesTheFix(t *testing.T) {
	s := New(&config.Config{})
	reached := false
	core := httptest.NewServer(s.withDuplex(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	})))
	t.Cleanup(core.Close)
	// The client gets HTTP/2 from the proxy, the core gets HTTP/1.1.
	upstream, err := url.Parse(core.URL)
	require.NoError(t, err)
	proxy := httptest.NewUnstartedServer(httputil.NewSingleHostReverseProxy(upstream))
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	t.Cleanup(proxy.Close)
	transport := connecthttp.NewTransport(proxy.Client(), proxy.URL)

	stream, err := nokkuv1connect.NewDaemonControlServiceClient(connect.NewClient(transport)).Connect(t.Context())
	require.NoError(t, err)
	// The request goes out with the first message.
	_ = stream.Send(&nokkuv1.ConnectRequest{})
	_, err = stream.Receive()
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnavailable, connect.CodeOf(err))
	require.ErrorContains(t, err, "h2c")
	assert.False(t, reached, "the stream must not reach its handler")

	_, _ = nokkuv1connect.NewUtilServiceClient(connect.NewClient(transport)).
		GetVersion(t.Context(), &nokkuv1.GetVersionRequest{})
	assert.True(t, reached, "a call that fits HTTP/1.1 goes through")
}

// A new two-way stream has to join the list, or it fails behind such a proxy without a word.
func TestDuplexProceduresAreAllListed(t *testing.T) {
	for _, procedure := range allProcedures(t) {
		name := protoreflect.FullName(strings.ReplaceAll(strings.TrimPrefix(procedure, "/"), "/", "."))
		d, err := protoregistry.GlobalFiles.FindDescriptorByName(name)
		require.NoError(t, err, procedure)
		md, ok := d.(protoreflect.MethodDescriptor)
		require.True(t, ok, procedure)
		assert.Equal(t, md.IsStreamingClient() && md.IsStreamingServer(), duplexProcedures[procedure], procedure)
	}
}
