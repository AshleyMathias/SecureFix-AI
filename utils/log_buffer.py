"""In-memory ring buffer of recent log events for the dashboard API."""
from __future__ import annotations

from collections import deque
from typing import Any, Dict, List

from structlog.types import EventDict, Processor

# Last N events (dashboard only needs recent activity)
_MAX_EVENTS = 300
_buffer: deque = deque(maxlen=_MAX_EVENTS)


def _sanitize(value: Any) -> Any:
    """Make event dict JSON-serializable."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [_sanitize(x) for x in value]
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    return str(value)


def _buffer_processor(
    logger: Any, method: str, event_dict: EventDict
) -> EventDict:
    """Structlog processor: append a copy of the event to the ring buffer."""
    # Capture events from securefix loggers, or any event with our "event" key (structured logs)
    logger_name = event_dict.get("logger", "")
    has_event = "event" in event_dict and isinstance(event_dict.get("event"), str)
    if "securefix" not in str(logger_name) and not has_event:
        return event_dict
    entry = {
        "timestamp": event_dict.get("timestamp"),
        "level": event_dict.get("level", method),
        "event": event_dict.get("event"),
        "message": event_dict.get("message"),
        "run_id": event_dict.get("run_id"),
        "run_id_short": (event_dict.get("run_id") or "")[:8] if event_dict.get("run_id") else None,
        "repo": event_dict.get("repo") or event_dict.get("repository"),
        "repo_url": event_dict.get("repo_url"),
        "status": event_dict.get("status"),
        "vuln_count": event_dict.get("vuln_count"),
        "pr_url": event_dict.get("pr_url"),
        "delivery_id": event_dict.get("delivery_id"),
        "error": event_dict.get("error", "")[:200] if event_dict.get("error") else None,
    }
    entry = {k: v for k, v in entry.items() if v is not None}
    _buffer.append(_sanitize(entry))
    return event_dict


def get_recent_logs(limit: int = 100, run_id: str | None = None) -> List[Dict[str, Any]]:
    """Return the most recent log entries, optionally filtered by run_id."""
    items = list(_buffer)
    if run_id:
        short = run_id[:8] if len(run_id) >= 8 else run_id
        items = [e for e in items if e.get("run_id") == run_id or e.get("run_id_short") == short or (e.get("run_id") and e.get("run_id", "")[:8] == short)]
    return items[-limit:]
