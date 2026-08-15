"""The four ZAP-backed category agents: SQLi, XSS, Auth, Misconfiguration.

Each is a thin LangGraph node over the shared ZAP-category helper, kept as
separate nodes so the graph matches the spec architecture.
"""

from __future__ import annotations

from .base import AgentContext, run_zap_category


def sqli_agent(ctx: AgentContext, state: dict) -> dict:
    return run_zap_category(ctx, state, "sqli")


def xss_agent(ctx: AgentContext, state: dict) -> dict:
    return run_zap_category(ctx, state, "xss")


def auth_agent(ctx: AgentContext, state: dict) -> dict:
    return run_zap_category(ctx, state, "auth")


def misconfig_agent(ctx: AgentContext, state: dict) -> dict:
    return run_zap_category(ctx, state, "misconfig")
