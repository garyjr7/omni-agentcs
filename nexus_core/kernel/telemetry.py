"""OpenTelemetry integration with a dependency-free no-op fallback."""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterator

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
    OTEL_AVAILABLE = True
except ImportError:
    trace = None
    Status = StatusCode = None
    OTEL_AVAILABLE = False


class Telemetry:
    def __init__(self, service_name: str = "nexus-kernel"):
        self.service_name = service_name
        self.tracer = trace.get_tracer(service_name) if OTEL_AVAILABLE else None

    @contextmanager
    def span(self, name: str, attributes: Dict[str, Any] | None = None) -> Iterator[Any]:
        if not self.tracer:
            yield None
            return
        with self.tracer.start_as_current_span(name, attributes=attributes or {}) as span:
            try:
                yield span
                span.set_status(Status(StatusCode.OK))
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                raise


telemetry = Telemetry()


class Metrics:
    """Small in-process metrics registry; exporters can scrape a safe snapshot."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: Dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}

    def increment(self, name: str, value: float = 1, **labels: str) -> None:
        key = (name, tuple(sorted((str(k), str(v)) for k, v in labels.items())))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + value

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [
                {"name": name, "labels": dict(labels), "value": value}
                for (name, labels), value in sorted(self._counters.items())
            ]


metrics = Metrics()


def configure_telemetry() -> bool:
    """Configure OTLP export when an endpoint is provided."""
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint or not OTEL_AVAILABLE:
        return False
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=Resource.create({
            "service.name": os.getenv("OTEL_SERVICE_NAME", "nexus")
        }))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
        telemetry.tracer = trace.get_tracer(telemetry.service_name)
        return True
    except Exception:
        return False
