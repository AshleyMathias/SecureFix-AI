from __future__ import annotations

import logging
import sys
from typing import Any, Dict, Optional

import structlog
from structlog.types import EventDict, Processor


def _add_severity_field(
    logger: Any, method: str, event_dict: EventDict
) -> EventDict:
    """Map structlog level names to Google Cloud / Datadog severity keys."""
    level = event_dict.get("level", method).upper()
    event_dict["severity"] = level
    return event_dict


def _drop_color_message_key(
    logger: Any, method: str, event_dict: EventDict
) -> EventDict:
    """Remove uvicorn's colour_message key to keep logs clean."""
    event_dict.pop("color_message", None)
    return event_dict


def configure_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    """
    Configure structlog with either JSON (production) or human-readable (dev) output.
    Must be called once at application startup.
    """
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        _add_severity_field,
        _drop_color_message_key,
    ]

    if log_format == "json":
        renderer: Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level.upper())

    # Silence noisy third-party loggers
    for noisy in ("httpx", "httpcore", "urllib3", "git", "github"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str, **initial_values: Any) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger with optional initial context values."""
    logger = structlog.get_logger(name)
    if initial_values:
        logger = logger.bind(**initial_values)
    return logger


class EventLogger:
    """
    Convenience wrapper that emits structured security-audit events
    with a consistent schema understood by SIEM tools.
    """

    def __init__(self, component: str) -> None:
        self._log = get_logger("securefix.events", component=component)

    def webhook_received(self, event: str, repo: str, delivery_id: Optional[str] = None) -> None:
        self._log.info(
            "webhook_received",
            event_type=event,
            repository=repo,
            delivery_id=delivery_id,
        )

    def scan_started(self, run_id: str, repo: str, scanners: list[str]) -> None:
        self._log.info(
            "scan_started",
            run_id=run_id,
            repository=repo,
            scanners=scanners,
        )

    def vulnerability_detected(
        self,
        run_id: str,
        vuln_id: str,
        package: str,
        severity: str,
        source: str,
    ) -> None:
        self._log.warning(
            "vulnerability_detected",
            run_id=run_id,
            vulnerability_id=vuln_id,
            package=package,
            severity=severity,
            source=source,
        )

    def patch_applied(
        self,
        run_id: str,
        package: str,
        from_version: str,
        to_version: str,
        branch: str,
    ) -> None:
        self._log.info(
            "patch_applied",
            run_id=run_id,
            package=package,
            from_version=from_version,
            to_version=to_version,
            branch=branch,
        )

    def tests_passed(self, run_id: str, ecosystem: str) -> None:
        self._log.info("tests_passed", run_id=run_id, ecosystem=ecosystem)

    def tests_failed(self, run_id: str, ecosystem: str, stderr: str) -> None:
        self._log.error(
            "tests_failed",
            run_id=run_id,
            ecosystem=ecosystem,
            stderr=stderr[:500],
        )

    def pull_request_created(
        self,
        run_id: str,
        repo: str,
        pr_number: int,
        pr_url: str,
    ) -> None:
        self._log.info(
            "pull_request_created",
            run_id=run_id,
            repository=repo,
            pr_number=pr_number,
            pr_url=pr_url,
        )

    def workflow_completed(
        self,
        run_id: str,
        status: str,
        duration_seconds: Optional[float] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._log.info(
            "workflow_completed",
            run_id=run_id,
            status=status,
            duration_seconds=duration_seconds,
            **(extra or {}),
        )
