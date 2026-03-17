from __future__ import annotations

import logging
import sys
from typing import Any, Dict, Optional

import structlog
from structlog.types import EventDict, Processor

from utils.log_buffer import _buffer_processor


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


def _add_readable_message(
    logger: Any, method: str, event_dict: EventDict
) -> EventDict:
    """Add a short human-readable 'message' so logs are easy to follow without losing data."""
    event = event_dict.get("event", "")
    run_id = (event_dict.get("run_id") or "")[:8]
    err = event_dict.get("error") or event_dict.get("error_message") or ""
    if err and len(err) > 200:
        err = err[:197] + "..."

    # Templates use {key} and are filled from event_dict; use run_id_short for brevity
    d = dict(event_dict)
    d["run_id_short"] = run_id
    d["error_short"] = err

    _templates: Dict[str, str] = {
        "webhook_received": "Webhook: {event_type} for {repository}",
        "workflow_dispatched": "Dispatching workflow for {repo} (event: {webhook_event})",
        "workflow_dispatched_issue": "Dispatching workflow for {repo} (issue #{issue_number}: {issue_title})",
        "securefix_ai_starting": "SecureFix AI starting (v{version}, {environment})",
        "securefix_ai_shutting_down": "SecureFix AI shutting down",
        "orchestrator_initialized": "Orchestrator ready (LLM: {llm_provider}/{llm_model})",
        "securefix_agent_ready": "Agent ready",
        "agent_run_starting": "Run {run_id_short}: starting for {repo_url}",
        "node_initialize": "Run {run_id_short}: initializing (cloning repo)",
        "cloning_repository": "Cloning repo → {dest}",
        "clone_complete": "Clone done: {path}",
        "clone_failed": "Clone failed: {error_short}",
        "node_detect": "Run {run_id_short}: scanning for vulnerabilities",
        "scan_all_starting": "Run {run_id_short}: running scanners {scanners}",
        "scan_all_complete": "Scan done: {total} vulns ({critical} critical, {high} high)",
        "detection_complete": "Run {run_id_short}: detection done ({total} vulns, {patchable} patchable)",
        "detect_skipped_no_repo_path": "Run {run_id_short}: scan skipped (no clone path)",
        "workflow_aborted": "Run {run_id_short}: aborted — {error_short}",
        "workflow_completed": "Run {run_id_short}: completed (status={status}, pr={pr_url})",
        "agent_run_complete": "Run complete: status={status}, vulns={vuln_count}, pr={pr_url}",
        "background_workflow_done": "Background run done: {status}",
        "webhook_event_ignored": "Webhook ignored (event: {webhook_event})",
        "issue_event_ignored": "Issue event ignored (action: {action})",
        "push_not_on_default_branch": "Push ignored (not default branch)",
        "routing_no_vulnerabilities": "No vulnerabilities → completing",
        "pull_request_created": "PR created: #{pr_number} {pr_url}",
        "repo_cleanup_complete": "Cleanup: removed clone at {path}",
    }

    # For workflow_dispatched with issue context, use issue-specific message
    if event == "workflow_dispatched" and d.get("issue_number") is not None and d.get("issue_title") is not None:
        event_dict["message"] = _templates["workflow_dispatched_issue"].format(
            **{k: v if isinstance(v, (str, int, float, type(None))) else str(v) for k, v in d.items()}
        )
        return event_dict

    template = _templates.get(event)
    if template:
        try:
            # Coerce values to str so list/dict don't break format
            safe = {k: v if isinstance(v, (str, int, float, type(None))) else str(v) for k, v in d.items()}
            event_dict["message"] = template.format(**safe)
        except (KeyError, TypeError):
            event_dict["message"] = event
    else:
        event_dict["message"] = event
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
        _add_readable_message,
        _buffer_processor,
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
