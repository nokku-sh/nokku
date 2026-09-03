package api

import (
	"context"
	"log/slog"
	"os"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/mizuchilabs/kata/buildinfo"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

func NewOTLPInterceptor(ctx context.Context) connect.Interceptor {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return nil
	}
	// Reads OTEL_EXPORTER_OTLP_ENDPOINT and OTEL_EXPORTER_OTLP_HEADERS from environment
	traceExporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithCompressor("gzip"))
	if err != nil {
		slog.Error("failed to init otlp exporter", "exporter", "trace", "error", err)
		return nil
	}
	metricExporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithCompressor("gzip"))
	if err != nil {
		slog.Error("failed to init otlp exporter", "exporter", "metric", "error", err)
		return nil
	}
	logExporter, err := otlploggrpc.New(ctx, otlploggrpc.WithCompressor("gzip"))
	if err != nil {
		slog.Error("failed to init otlp exporter", "exporter", "log", "error", err)
		return nil
	}

	res, err := resource.New(
		ctx,
		resource.WithTelemetrySDK(),
		resource.WithFromEnv(),
		resource.WithOS(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String("nokku"),
			semconv.ServiceVersionKey.String(buildinfo.Version),
		),
	)
	if err != nil {
		slog.Warn("failed to create otel resource", "error", err)
		return nil
	}
	tp := trace.NewTracerProvider(
		trace.WithBatcher(traceExporter),
		trace.WithResource(res),
		trace.WithSampler(trace.ParentBased(trace.TraceIDRatioBased(0.1))),
	)
	otel.SetTracerProvider(tp)

	mp := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(metricExporter)),
		metric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	lp := log.NewLoggerProvider(
		log.WithProcessor(log.NewBatchProcessor(logExporter)),
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

	interceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		slog.Warn("failed to create otel interceptor", "error", err)
		return nil
	}

	go func() {
		<-ctx.Done()
		bg := context.WithoutCancel(ctx)

		if lp != nil {
			_ = lp.Shutdown(bg)
		}
		if mp != nil {
			_ = mp.Shutdown(bg)
		}
		if tp != nil {
			_ = tp.Shutdown(bg)
		}
	}()
	return interceptor
}
