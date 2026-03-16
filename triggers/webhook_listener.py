from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

import structlog
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from utils.config import get_settings
from utils.logger import configure_logging, get_logger, EventLogger
from workflows.vulnerability_fix_flow import VulnerabilityFixFlow, WorkflowResult

# ── Bootstrap ──────────────────────────────────────────────────────────────────

settings = get_settings()
configure_logging(settings.log_level, settings.log_format)

logger = get_logger("securefix.webhook")
events = EventLogger("webhook_listener")


# ── Application Lifecycle ──────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "securefix_ai_starting",
        version=settings.app_version,
        environment=settings.environment,
        llm_provider=settings.llm_provider,
    )
    yield
    logger.info("securefix_ai_shutting_down")


app = FastAPI(
    title="SecureFix AI",
    description=(
        "Autonomous DevSecOps agent that monitors GitHub repositories for "
        "dependency vulnerabilities and automatically generates secure patches."
    ),
    version=settings.app_version,
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    lifespan=lifespan,
)

# ── Shared workflow instance ───────────────────────────────────────────────────
_flow: Optional[VulnerabilityFixFlow] = None


def get_flow() -> VulnerabilityFixFlow:
    global _flow
    if _flow is None:
        _flow = VulnerabilityFixFlow()
    return _flow


# ── Webhook Signature Verification ────────────────────────────────────────────

def _verify_github_signature(body: bytes, signature_header: Optional[str]) -> None:
    """
    Validate the X-Hub-Signature-256 header against the configured webhook secret.
    Raises HTTP 401 if verification fails.
    """
    if not settings.github_webhook_secret:
        return  # Signature checking disabled (dev mode)

    if not signature_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Hub-Signature-256 header missing.",
        )

    expected = "sha256=" + hmac.new(
        settings.github_webhook_secret.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GitHub webhook signature verification failed.",
        )


# ── Background task wrapper ───────────────────────────────────────────────────

async def _run_workflow_background(
    repo_url: str,
    event_type: str,
    payload: Dict[str, Any],
    delivery_id: str,
) -> None:
    """Run the full SecureFix workflow and log the outcome."""
    try:
        result: WorkflowResult = await get_flow().run_for_repository(
            repo_url=repo_url,
            base_branch=payload.get("repository", {}).get("default_branch", "main"),
            triggered_by="webhook",
            webhook_event=event_type,
            webhook_payload=payload,
            run_id=delivery_id,
        )
        logger.info(
            "background_workflow_done",
            delivery_id=delivery_id,
            status=result.status,
            pr_url=result.pr_url,
        )
    except Exception as exc:
        logger.error("background_workflow_failed", delivery_id=delivery_id, error=str(exc))


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post(
    "/github/webhook",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive GitHub webhook events",
    tags=["Webhook"],
)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: Optional[str] = Header(default=None),
    x_hub_signature_256: Optional[str] = Header(default=None),
    x_github_delivery: Optional[str] = Header(default=None),
) -> JSONResponse:
    """
    Entry point for all GitHub webhook events.

    Supported events:
    - push
    - pull_request
    - repository_vulnerability_alert
    - workflow_run
    - schedule (via GitHub Actions)
    """
    body = await request.body()
    _verify_github_signature(body, x_hub_signature_256)

    try:
        payload: Dict[str, Any] = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload.",
        )

    event_type = x_github_event or "unknown"
    delivery_id = x_github_delivery or "no-delivery-id"
    repo_info = payload.get("repository", {})
    repo_url = repo_info.get("clone_url") or repo_info.get("html_url", "")
    repo_name = repo_info.get("full_name", "unknown")

    events.webhook_received(event_type, repo_name, delivery_id)

    # Filter events we actually care about
    handled_events = {
        "push",
        "pull_request",
        "repository_vulnerability_alert",
        "workflow_run",
        "schedule",
    }

    if event_type not in handled_events:
        logger.debug("webhook_event_ignored", event=event_type)
        return JSONResponse(
            content={"status": "ignored", "event": event_type},
            status_code=status.HTTP_200_OK,
        )

    if not repo_url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Cannot extract repository URL from payload.",
        )

    # For push events, only trigger on default branch pushes
    if event_type == "push":
        default_branch = repo_info.get("default_branch", "main")
        pushed_ref = payload.get("ref", "")
        if pushed_ref != f"refs/heads/{default_branch}":
            logger.debug(
                "push_not_on_default_branch",
                ref=pushed_ref,
                default=default_branch,
            )
            return JSONResponse(
                content={"status": "ignored", "reason": "not default branch"},
                status_code=status.HTTP_200_OK,
            )

    # Dispatch to background task immediately (respond fast to GitHub)
    background_tasks.add_task(
        _run_workflow_background,
        repo_url=repo_url,
        event_type=event_type,
        payload=payload,
        delivery_id=delivery_id,
    )

    logger.info(
        "workflow_dispatched",
        event=event_type,
        repo=repo_name,
        delivery_id=delivery_id,
    )

    return JSONResponse(
        content={
            "status": "accepted",
            "event": event_type,
            "repository": repo_name,
            "run_id": delivery_id,
        }
    )


class ManualScanRequest(BaseModel):
    repo_url: str
    base_branch: str = "main"


@app.post(
    "/scan",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Manually trigger a repository scan",
    tags=["API"],
)
async def manual_scan(
    request: ManualScanRequest,
    background_tasks: BackgroundTasks,
) -> JSONResponse:
    """
    Manually trigger a vulnerability scan for a given repository.
    Useful for testing and CLI-based invocations.
    """
    import uuid
    run_id = str(uuid.uuid4())

    background_tasks.add_task(
        _run_workflow_background,
        repo_url=request.repo_url,
        event_type="manual",
        payload={"repository": {"default_branch": request.base_branch}},
        delivery_id=run_id,
    )

    logger.info("manual_scan_dispatched", repo_url=request.repo_url, run_id=run_id)

    return JSONResponse(
        content={
            "status": "accepted",
            "repo_url": request.repo_url,
            "run_id": run_id,
        }
    )


@app.get(
    "/health",
    summary="Health check",
    tags=["System"],
)
async def health() -> JSONResponse:
    return JSONResponse(
        content={
            "status": "healthy",
            "version": settings.app_version,
            "environment": settings.environment,
            "llm_provider": settings.llm_provider,
        }
    )


@app.get(
    "/",
    summary="Root",
    tags=["System"],
    include_in_schema=False,
)
async def root() -> JSONResponse:
    return JSONResponse(
        content={
            "name": "SecureFix AI",
            "version": settings.app_version,
            "docs": "/docs",
        }
    )
