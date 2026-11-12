package api

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"connectrpc.com/connect/v2"
	"connectrpc.com/otelconnect"
	"github.com/mizuchilabs/kata/buildinfo"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/contrib/processors/minsev"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// telemetry is off without an OTLP endpoint. The rest follows OTEL_*.
func telemetry(ctx context.Context) connect.ServerInterceptor {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return noTelemetry
	}
	traceExporter, err := otlptracehttp.New(ctx)
	if err != nil {
		slog.Error("failed to init otel exporter", "exporter", "trace", "error", err)
		return noTelemetry
	}
	metricExporter, err := otlpmetrichttp.New(ctx)
	if err != nil {
		slog.Error("failed to init otel exporter", "exporter", "metric", "error", err)
		return noTelemetry
	}
	logExporter, err := otlploghttp.New(ctx)
	if err != nil {
		slog.Error("failed to init otel exporter", "exporter", "log", "error", err)
		return noTelemetry
	}

	res, err := resource.New(
		ctx,
		resource.WithTelemetrySDK(),
		resource.WithOS(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String("nokku"),
			semconv.ServiceVersionKey.String(buildinfo.Version),
		),
		// Last, so OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES win.
		resource.WithFromEnv(),
	)
	if err != nil {
		slog.Warn("failed to create otel resource", "error", err)
		return noTelemetry
	}
	tp := trace.NewTracerProvider(
		trace.WithBatcher(traceExporter),
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	mp := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(metricExporter)),
		metric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	lp := log.NewLoggerProvider(
		log.WithProcessor(minsev.NewLogProcessor(log.NewBatchProcessor(logExporter), minsev.SeverityWarn)),
		log.WithResource(res),
	)

	otelLogger := slog.New(slog.NewMultiHandler(
		slog.Default().Handler(),
		otelslog.NewLogger("nokku-api", otelslog.WithLoggerProvider(lp)).Handler(),
	))
	slog.SetDefault(otelLogger)

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if err := runtime.Start(); err != nil {
		slog.Warn("failed to start runtime metrics", "error", err)
	}

	// Nothing waits for this flush, so the last seconds may never arrive.
	context.AfterFunc(ctx, func() {
		bg := context.WithoutCancel(ctx)
		_ = lp.Shutdown(bg)
		_ = mp.Shutdown(bg)
		_ = tp.Shutdown(bg)
	})

	interceptor, err := otelconnect.NewServerInterceptor()
	if err != nil {
		slog.Warn("failed to create otel interceptor", "error", err)
		return noTelemetry
	}
	return interceptor
}

func noTelemetry(next connect.ServerFunc) connect.ServerFunc { return next }

// withTrace covers plain HTTP routes, the otelconnect interceptor the RPCs.
// It is a no-op until telemetry sets the global providers.
func (s *Server) withTrace(next http.Handler) http.Handler {
	traced := otelhttp.NewHandler(next, "http",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string { return r.Pattern }),
		// Anyone can send a traceparent, so it becomes a link and never a parent.
		otelhttp.WithPublicEndpointFn(func(*http.Request) bool { return true }),
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := s.mux.Handler(r)
		if !tracedRoute(r.URL.Path, pattern) {
			next.ServeHTTP(w, r)
			return
		}
		// Middleware copies the request, so the mux's own Pattern never gets back here.
		r.Pattern = pattern
		traced.ServeHTTP(w, r)
	})
}

// tracedRoute skips RPCs, static files, probes and terminals, which last for hours.
func tracedRoute(path, pattern string) bool {
	switch pattern {
	case "", "/", "/healthz", "GET /terminal/ws":
		return false
	}
	return !strings.HasPrefix(path, "/nokku.v1.")
}
