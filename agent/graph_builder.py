from __future__ import annotations

from langgraph.graph import StateGraph, END

from agent.state import SecureFixState
from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger("securefix.graph")

# ── Node name constants ────────────────────────────────────────────────────────
NODE_INIT = "initialize"
NODE_DETECT = "detect_vulnerabilities"
NODE_REASON = "ai_reasoning"
NODE_UPDATE = "update_dependencies"
NODE_PATCH = "apply_patch"
NODE_TEST = "run_tests"
NODE_PR = "create_pull_request"
NODE_COMPLETE = "complete"
NODE_ABORT = "abort"


def build_graph(orchestrator: "SecureFixOrchestrator") -> StateGraph:
    """
    Construct the LangGraph workflow graph for SecureFix AI.

    Node execution order:
        initialize
            ↓
        detect_vulnerabilities
            ↓ (vulnerabilities found) / → complete (none found)
        ai_reasoning
            ↓
        update_dependencies
            ↓
        apply_patch
            ↓ (success) / → abort (failure)
        run_tests
            ↓ (passed) / → abort (failed + abort_on_failure)
        create_pull_request
            ↓
        complete

    Error handling:
        Any node can set should_abort=True to route to the abort node,
        which logs the failure and terminates the graph gracefully.
    """
    graph = StateGraph(SecureFixState)

    # Register nodes
    graph.add_node(NODE_INIT, orchestrator.initialize)
    graph.add_node(NODE_DETECT, orchestrator.detect_vulnerabilities)
    graph.add_node(NODE_REASON, orchestrator.ai_reasoning)
    graph.add_node(NODE_UPDATE, orchestrator.update_dependencies)
    graph.add_node(NODE_PATCH, orchestrator.apply_patch)
    graph.add_node(NODE_TEST, orchestrator.run_tests)
    graph.add_node(NODE_PR, orchestrator.create_pull_request)
    graph.add_node(NODE_COMPLETE, orchestrator.complete)
    graph.add_node(NODE_ABORT, orchestrator.abort)

    # Entry point
    graph.set_entry_point(NODE_INIT)

    # Fixed edges
    graph.add_edge(NODE_INIT, NODE_DETECT)
    graph.add_edge(NODE_REASON, NODE_UPDATE)
    graph.add_edge(NODE_UPDATE, NODE_PATCH)
    graph.add_edge(NODE_PR, NODE_COMPLETE)
    graph.add_edge(NODE_COMPLETE, END)
    graph.add_edge(NODE_ABORT, END)

    # Conditional: after detection
    graph.add_conditional_edges(
        NODE_DETECT,
        _route_after_detection,
        {
            "reason": NODE_REASON,
            "complete": NODE_COMPLETE,
            "abort": NODE_ABORT,
        },
    )

    # Conditional: after patch
    graph.add_conditional_edges(
        NODE_PATCH,
        _route_after_patch,
        {
            "test": NODE_TEST,
            "abort": NODE_ABORT,
        },
    )

    # Conditional: after tests
    graph.add_conditional_edges(
        NODE_TEST,
        _route_after_tests,
        {
            "pr": NODE_PR,
            "abort": NODE_ABORT,
        },
    )

    logger.debug("langgraph_built", nodes=list(graph.nodes))
    return graph


# ── Routing functions ──────────────────────────────────────────────────────────

def _route_after_detection(state: SecureFixState) -> str:
    if state.get("should_abort"):
        return "abort"
    vulns = state.get("vulnerabilities", [])
    if not vulns:
        logger.info("routing_no_vulnerabilities")
        return "complete"
    patchable = [v for v in vulns if v.is_patchable]
    if not patchable:
        logger.info("routing_no_patchable_vulnerabilities", total=len(vulns))
        return "complete"
    return "reason"


def _route_after_patch(state: SecureFixState) -> str:
    if state.get("should_abort"):
        return "abort"
    if not state.get("patch_success", False):
        return "abort"
    return "test"


def _route_after_tests(state: SecureFixState) -> str:
    if state.get("should_abort"):
        return "abort"

    settings = get_settings()

    if not state.get("tests_passed", True) and settings.abort_on_test_failure:
        logger.warning("routing_tests_failed_aborting")
        return "abort"
    return "pr"
