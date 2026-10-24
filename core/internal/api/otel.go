package api

import (
	"context"
	"log/slog"
	"os"

	"connectrpc.com/connect/v2"
	"connectrpc.com/otelconnect"
	"github.com/mizuchilabs/kata/buildinfo"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/contrib/processors/minsev"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// newTelemetry turns OTel on when an OTLP endpoint is set. Everything else follows the OTEL_* environment.
func newTelemetry(ctx context.Context) connect.ServerInterceptor {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return nil
	}
	traceExporter, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		slog.Error("failed to init otel exporter", "exporter", "trace", "error", err)
		return nil
	}
	metricReader, err := autoexport.NewMetricReader(ctx)
	if err != nil {
		slog.Error("failed to init otel exporter", "exporter", "metric", "error", err)
		return nil
	}
	logExporter, err := autoexport.NewLogExporter(ctx)
	if err != nil {
		slog.Error("failed to init otel exporter", "exporter", "log", "error", err)
		return nil
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
		return nil
	}
	tp := trace.NewTracerProvider(
		trace.WithBatcher(traceExporter),
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	mp := metric.NewMeterProvider(
		metric.WithReader(metricReader),
		metric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	// The collector gets warnings and errors, nothing below.
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

	// Nothing waits for the flush, the last seconds before an exit may not arrive.
	context.AfterFunc(ctx, func() {
		bg := context.WithoutCancel(ctx)
		_ = lp.Shutdown(bg)
		_ = mp.Shutdown(bg)
		_ = tp.Shutdown(bg)
	})

	interceptor, err := otelconnect.NewServerInterceptor()
	if err != nil {
		slog.Warn("failed to create otel interceptor", "error", err)
		return nil
	}
	return interceptor
}
