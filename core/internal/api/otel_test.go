package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// All three signals reach a collector over OTLP HTTP on the standard variable.
func TestTelemetryExportsOverHTTP(t *testing.T) {
	var mu sync.Mutex
	got := map[string]bool{}
	collector := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		got[r.URL.Path] = true
	}))
	t.Cleanup(collector.Close)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.URL)

	logger, tracer, meter := slog.Default(), otel.GetTracerProvider(), otel.GetMeterProvider()
	t.Cleanup(func() {
		slog.SetDefault(logger)
		otel.SetTracerProvider(tracer)
		otel.SetMeterProvider(meter)
	})

	// newTelemetry wraps the default handler, and Go's own loops through log.
	slog.SetDefault(slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	require.NotNil(t, newTelemetry(ctx), "telemetry stayed off with an endpoint set")

	_, span := otel.Tracer("test").Start(ctx, "request")
	span.End()
	slog.Warn("a line for the collector")
	cancel()

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return got["/v1/traces"] && got["/v1/metrics"] && got["/v1/logs"]
	}, 10*time.Second, 20*time.Millisecond, "not every signal reached the collector")
}

func TestWithTraceCoversPlainRoutesOnly(t *testing.T) {
	spans := tracetest.NewSpanRecorder()
	provider, propagator := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans)))
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(provider)
		otel.SetTextMapPropagator(propagator)
	})

	s := New(nil)
	var inHandler trace.SpanContext
	ok := func(_ http.ResponseWriter, r *http.Request) {
		inHandler = trace.SpanContextFromContext(r.Context())
	}
	s.mux.HandleFunc("POST /passkey/login/begin", ok)
	s.mux.HandleFunc("/nokku.v1.UtilService/", ok)
	s.mux.HandleFunc("/healthz", ok)
	s.mux.HandleFunc("GET /terminal/ws", ok)
	s.mux.HandleFunc("/", ok)

	// A copy, like the real middleware makes.
	h := s.withTrace(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mux.ServeHTTP(w, r.WithContext(r.Context()))
	}))

	for _, target := range []string{
		"/nokku.v1.UtilService/GetVersion", "/healthz", "/terminal/ws", "/assets/app.js",
	} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, target, nil))
		assert.Empty(t, spans.Ended(), "%s got an HTTP span", target)
	}

	r := httptest.NewRequest(http.MethodPost, "/passkey/login/begin?token=secret", nil)
	const remote = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	r.Header.Set("Traceparent", remote)
	h.ServeHTTP(httptest.NewRecorder(), r)

	require.Len(t, spans.Ended(), 1, "the plain route got no span")
	span := spans.Ended()[0]
	assert.Equal(t, "POST /passkey/login/begin", span.Name())
	assert.Contains(t, span.Attributes(),
		attribute.String("http.route", "/passkey/login/begin"))
	assert.Equal(t, span.SpanContext().SpanID(), inHandler.SpanID(), "the handler lost the span")
	assert.False(t, span.Parent().IsValid(), "a client picked the parent span")
	assert.Len(t, span.Links(), 1, "the client's traceparent was dropped")
	for _, attr := range span.Attributes() {
		assert.NotContains(t, attr.Value.String(), "secret", "the query reached %s", attr.Key)
	}
}
