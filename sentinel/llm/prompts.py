"""Narrow, category-specific prompts.

Key principle (spec Section 3): the LLM's job is to interpret, confirm, and
explain tool output — never to invent findings. Every prompt is grounded in the
raw scan JSON we pass in, and the model is told to only report what the evidence
supports.
"""

from __future__ import annotations

CATEGORY_GUIDANCE = {
    "recon": (
        "You are a reconnaissance analyst. You are given raw Nmap scan output. "
        "Identify open ports, running services, versions, and anything that "
        "widens the attack surface (admin panels, outdated services, unusual ports)."
    ),
    "sqli": (
        "You are a SQL injection specialist. You are given raw OWASP ZAP alert "
        "output. Identify likely SQL injection findings: which endpoint and "
        "parameter, the injection evidence, and how confident the tool was."
    ),
    "xss": (
        "You are a Cross-Site Scripting (XSS) specialist. You are given raw OWASP "
        "ZAP alert output. Identify reflected, stored, or DOM XSS findings with the "
        "affected endpoint/parameter and the reflected payload evidence."
    ),
    "auth": (
        "You are a broken-authentication specialist. You are given raw OWASP ZAP "
        "alert output plus session/cookie observations. Identify weak session "
        "handling, missing account lockout, default credentials, and insecure "
        "cookie flags."
    ),
    "misconfig": (
        "You are a security-misconfiguration specialist. You are given raw OWASP "
        "ZAP alert output. Identify exposed/verbose headers, missing security "
        "headers, directory listing, default/backup files, and information leaks."
    ),
}

INTERPRET_SYSTEM = (
    "You are a component of an automated penetration-testing pipeline. "
    "You ONLY interpret real scanner output — you must never invent vulnerabilities "
    "that are not supported by the provided evidence. If the raw output contains no "
    "credible finding for your category, return an empty list. Be precise and "
    "conservative."
)

CONFIRM_SYSTEM = (
    "You are the findings-confirmation reviewer in an automated penetration test. "
    "You receive ALL raw findings gathered by category agents from OWASP ZAP and "
    "Nmap. For each finding decide whether it is a credible issue or a likely false "
    "positive, assign a qualitative severity (informational/low/medium/high/critical) "
    "using CVSS-informed reasoning, deduplicate, and write concise remediation "
    "advice. Raw scanners are noisy — discard or down-rank low-confidence noise, but "
    "never discard a well-evidenced high-impact finding. Ground every decision in the "
    "provided evidence."
)

REPORT_SYSTEM = (
    "You are a senior penetration tester writing the final report. Write clear, "
    "professional prose suitable for both executives and engineers. Base every "
    "statement strictly on the confirmed findings provided. Do not exaggerate and do "
    "not introduce findings that are not in the data."
)


def interpret_user_prompt(category: str, target: str, raw_json: str) -> str:
    guidance = CATEGORY_GUIDANCE.get(category, "")
    return (
        f"{guidance}\n\n"
        f"Target under test: {target}\n\n"
        f"Raw scan output (JSON):\n```json\n{raw_json}\n```\n\n"
        "Return findings that are directly supported by this output. For each "
        "finding provide: endpoint, param (if any), name, description, evidence "
        "(quoted from the raw output), confidence (low/medium/high), and a short "
        "remediation hint. If nothing credible is present, return an empty list."
    )


def confirm_user_prompt(target: str, raw_json: str) -> str:
    return (
        f"Target under test: {target}\n\n"
        f"All raw category findings (JSON):\n```json\n{raw_json}\n```\n\n"
        "Produce the confirmed finding set. For each: category, endpoint, name, "
        "severity, confidence, evidence, description, remediation, and set "
        "false_positive=true (with reasoning) for anything you are discarding as "
        "noise. Merge duplicates that describe the same issue on the same endpoint."
    )


def report_user_prompt(target: str, confirmed_json: str, meta_json: str) -> str:
    return (
        "Write a Markdown penetration-test report with these sections in order:\n"
        "1. Executive Summary\n2. Scope & Methodology\n3. Findings Summary Table "
        "(Category | Severity | Endpoint | Confidence)\n4. Detailed Findings "
        "(one subsection each, with evidence and remediation)\n"
        "5. Recommendations.\n\n"
        f"Target: {target}\n\n"
        f"Scan metadata (JSON):\n```json\n{meta_json}\n```\n\n"
        f"Confirmed findings (JSON):\n```json\n{confirmed_json}\n```\n\n"
        "Only report the confirmed (non false-positive) findings in the detailed "
        "sections. Keep the executive summary to a short paragraph."
    )
