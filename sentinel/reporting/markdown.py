"""Deterministic Markdown report template.

Used directly when running offline (no Claude), and also as a structured
fallback. The Claude-authored report is prose; this one is a reliable template
that always renders whatever confirmed findings exist.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}


def _sort_key(f: dict) -> tuple:
    return (_SEVERITY_ORDER.get(f.get("severity", "low"), 5), f.get("category", ""))


def render_markdown(target: str, confirmed: list[dict], meta: dict[str, Any]) -> str:
    kept = sorted(
        (f for f in confirmed if not f.get("false_positive")), key=_sort_key
    )
    counts: dict[str, int] = {}
    for f in kept:
        counts[f.get("severity", "unknown")] = counts.get(f.get("severity", "unknown"), 0) + 1

    generated = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines: list[str] = []
    lines.append(f"# Penetration Test Report — {target}")
    lines.append("")
    lines.append(f"*Generated: {generated} · Scan ID: {meta.get('scan_id', 'n/a')}*")
    lines.append("")

    # 1. Executive summary
    lines.append("## 1. Executive Summary")
    lines.append("")
    if kept:
        summary_bits = ", ".join(f"{n} {sev}" for sev, n in sorted(
            counts.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 5)))
        lines.append(
            f"An automated assessment of `{target}` identified **{len(kept)} confirmed "
            f"finding(s)** ({summary_bits}). The most severe issues should be "
            "remediated first; details and remediation guidance follow."
        )
    else:
        lines.append(
            f"An automated assessment of `{target}` did not confirm any material "
            "findings after false-positive filtering."
        )
    lines.append("")

    # 2. Scope & methodology
    lines.append("## 2. Scope & Methodology")
    lines.append("")
    lines.append(f"- **Target:** `{target}`")
    lines.append(f"- **Tools:** OWASP ZAP (active scan), Nmap (service discovery)")
    lines.append(
        f"- **Analysis engine:** {meta.get('llm_backend', 'heuristic')} "
        f"({meta.get('model', 'n/a')})"
    )
    lines.append(
        f"- **Data source:** {meta.get('data_source', 'sample data (mock)' if meta.get('mock') else 'live tools')}"
    )
    lines.append(
        "- **Categories:** Recon, SQL Injection, Cross-Site Scripting, Broken "
        "Authentication, Security Misconfiguration"
    )
    lines.append("")

    # 3. Findings summary table
    lines.append("## 3. Findings Summary")
    lines.append("")
    if kept:
        lines.append("| # | Category | Severity | Confidence | Endpoint |")
        lines.append("|---|----------|----------|------------|----------|")
        for i, f in enumerate(kept, 1):
            lines.append(
                f"| {i} | {f.get('category', '')} | {f.get('severity', '')} | "
                f"{f.get('confidence', '')} | `{f.get('endpoint', '')}` |"
            )
    else:
        lines.append("_No confirmed findings._")
    lines.append("")

    # 4. Detailed findings
    lines.append("## 4. Detailed Findings")
    lines.append("")
    if not kept:
        lines.append("_None._")
    for i, f in enumerate(kept, 1):
        lines.append(
            f"### 4.{i} {f.get('name', 'Finding')} "
            f"({f.get('severity', 'unknown').title()})"
        )
        lines.append("")
        lines.append(f"- **Category:** {f.get('category', '')}")
        lines.append(f"- **Endpoint:** `{f.get('endpoint', '')}`")
        lines.append(f"- **Confidence:** {f.get('confidence', '')}")
        lines.append("")
        if f.get("description"):
            lines.append(f"**Description.** {f['description']}")
            lines.append("")
        if f.get("evidence"):
            lines.append("**Evidence.**")
            lines.append("")
            lines.append("```")
            lines.append(str(f["evidence"]))
            lines.append("```")
            lines.append("")
        if f.get("remediation"):
            lines.append(f"**Remediation.** {f['remediation']}")
            lines.append("")

    # 5. Recommendations
    lines.append("## 5. Recommendations")
    lines.append("")
    if kept:
        lines.append(
            "Prioritise remediation by severity (critical/high first). Adopt "
            "parameterised queries, contextual output encoding, secure cookie "
            "flags, anti-CSRF tokens, and a complete set of security response "
            "headers. Re-scan after fixes to confirm closure."
        )
    else:
        lines.append("Maintain current controls and re-scan periodically.")
    lines.append("")

    # Appendix: false positives
    discarded = [f for f in confirmed if f.get("false_positive")]
    if discarded:
        lines.append("## Appendix A — Discarded (False Positives / Noise)")
        lines.append("")
        for f in discarded:
            lines.append(
                f"- `{f.get('endpoint', '')}` — {f.get('name', '')}: "
                f"{f.get('reasoning', 'discarded')}"
            )
        lines.append("")

    return "\n".join(lines)
