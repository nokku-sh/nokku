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
