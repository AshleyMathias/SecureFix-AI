from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from agent.graph_builder import build_graph
from agent.orchestrator import SecureFixOrchestrator
from agent.state import SecureFixState, initial_state
from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger("securefix.agent")


class SecureFixAgent:
    """
    High-level entry point for running a SecureFix workflow.

    Usage:
        agent = SecureFixAgent()
        result = await agent.run(repo_url="https://github.com/owner/repo")

    The agent compiles the LangGraph graph once and reuses it across invocations.
    Each run gets an isolated state with a unique run_id.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._orchestrator = SecureFixOrchestrator()
        self._graph = build_graph(self._orchestrator).compile()
        logger.info("securefix_agent_ready")

    async def run(
        self,
        repo_url: str,
        base_branch: str = "main",
        triggered_by: str = "api",
        webhook_event: Optional[str] = None,
        webhook_payload: Optional[Dict[str, Any]] = None,
        run_id: Optional[str] = None,
    ) -> SecureFixState:
        """
        Execute the full SecureFix vulnerability detection and patching workflow.

        Args:
            repo_url:        HTTPS GitHub repository URL.
            base_branch:     Branch to merge the security patch PR into.
            triggered_by:    Source of this run (webhook / api / schedule / cli).
            webhook_event:   GitHub webhook event type if triggered by webhook.
            webhook_payload: Full webhook payload for audit trail.
            run_id:          Optional explicit run identifier; auto-generated if omitted.

        Returns:
            Final SecureFixState after the graph completes or aborts.
        """
        if not run_id:
            run_id = str(uuid.uuid4())

        logger.info(
            "agent_run_starting",
            run_id=run_id,
            repo_url=repo_url,
            triggered_by=triggered_by,
        )

        state = initial_state(
            run_id=run_id,
            repo_url=repo_url,
            base_branch=base_branch,
            triggered_by=triggered_by,
            webhook_event=webhook_event,
            webhook_payload=webhook_payload,
        )

        try:
            final_state: SecureFixState = await self._graph.ainvoke(state)
        except Exception as exc:
            logger.error("agent_run_error", run_id=run_id, error=str(exc))
            state["status"] = "failed"
            state["error_message"] = str(exc)
            return state

        logger.info(
            "agent_run_complete",
            run_id=run_id,
            status=final_state.get("status"),
            pr_url=final_state.get("pr_url"),
            vuln_count=len(final_state.get("vulnerabilities", [])),
        )

        return final_state

    async def run_from_webhook(
        self,
        repo_url: str,
        event_type: str,
        payload: Dict[str, Any],
    ) -> SecureFixState:
        """
        Convenience wrapper for webhook-triggered runs.
        Extracts base_branch from the payload when available.
        """
        base_branch = (
            payload.get("repository", {}).get("default_branch", "main")
        )
        return await self.run(
            repo_url=repo_url,
            base_branch=base_branch,
            triggered_by="webhook",
            webhook_event=event_type,
            webhook_payload=payload,
        )
