"""LangGraph orchestrator wiring the multi-agent penetration-testing graph.

    START
      → orchestrator
          ├→ recon      (Nmap)
          ├→ sqli       (ZAP)
          ├→ xss        (ZAP)
          ├→ auth       (ZAP)
          └→ misconfig  (ZAP)
              → confirmation   (LLM: filter FPs + severity)
                  → report     (Markdown + PDF)
                      → END
"""

from __future__ import annotations

import uuid
from functools import partial

from langgraph.graph import END, START, StateGraph

from .agents.base import AgentContext
from .agents.confirmation import confirmation_agent
from .agents.recon import recon_agent
from .agents.report import report_agent
from .agents.scanners import auth_agent, misconfig_agent, sqli_agent, xss_agent
from .config import Settings, assert_in_scope
from .llm import LLMClient
from .state import ScanState
from .tools import NmapClient, ZapClient

_CATEGORY_NODES = {
    "recon": recon_agent,
    "sqli": sqli_agent,
    "xss": xss_agent,
    "auth": auth_agent,
    "misconfig": misconfig_agent,
}


def build_context(settings: Settings) -> AgentContext:
    return AgentContext(
        settings=settings,
        llm=LLMClient(settings),
        zap=ZapClient(settings),
        nmap=NmapClient(settings),
    )


def _orchestrator(ctx: AgentContext, state: dict) -> dict:
    return {
        "status": "scanning",
        "log": [
            f"[orchestrator] Starting scan of {state['target']} "
            f"(analysis={ctx.llm.backend}, mode={'mock' if state.get('mock') else 'live'})."
        ],
    }


def build_graph(ctx: AgentContext):
    graph = StateGraph(ScanState)

    graph.add_node("orchestrator", partial(_orchestrator, ctx))
    for name, fn in _CATEGORY_NODES.items():
        graph.add_node(name, partial(fn, ctx))
    graph.add_node("confirmation", partial(confirmation_agent, ctx))
    graph.add_node("report", partial(report_agent, ctx))

    graph.add_edge(START, "orchestrator")
    for name in _CATEGORY_NODES:
        graph.add_edge("orchestrator", name)  # fan out
        graph.add_edge(name, "confirmation")  # fan in (confirmation waits for all)
    graph.add_edge("confirmation", "report")
    graph.add_edge("report", END)

    return graph.compile()


def run_scan(target: str, settings: Settings | None = None) -> dict:
    """Convenience entrypoint: validate scope, run the graph, return final state."""
    settings = settings or Settings()
    host = assert_in_scope(target, settings)  # raises ScopeError if out of scope
    ctx = build_context(settings)
    app = build_graph(ctx)

    scan_id = str(uuid.uuid4())
    initial: dict = {
        "scan_id": scan_id,
        "target": target,
        "host": host,
        "status": "pending",
        "mock": settings.mock,
        "raw_results": {},
        "confirmed_findings": [],
        "errors": [],
        "log": [],
        "meta": {"scan_id": scan_id},
    }
    # Fan-out width is small; bump recursion limit headroom just in case.
    final = app.invoke(initial, config={"recursion_limit": 50})
    return final
