"""Phase 1 demo (spec Section 12): the core tool -> LLM -> interpretation loop.

A single agent, single tool, no orchestration. Runs one OWASP ZAP category scan
against a local target (or bundled sample data) and asks the LLM to interpret the
raw output. Proves the fundamental loop before any graph complexity.

    python scripts/phase1_demo.py --mock
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.config import Settings, assert_in_scope  # noqa: E402
from sentinel.llm import LLMClient  # noqa: E402
from sentinel.tools import ZapClient  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Phase 1: single tool -> LLM loop")
    ap.add_argument("--target", default="http://localhost/dvwa")
    ap.add_argument("--category", default="sqli", choices=["sqli", "xss", "auth", "misconfig"])
    ap.add_argument("--mock", action="store_true")
    args = ap.parse_args()

    settings = Settings()
    if args.mock:
        settings.mock = True
    assert_in_scope(args.target, settings)

    zap = ZapClient(settings)
    llm = LLMClient(settings)

    print(f"[1] Running ZAP ({args.category}) against {args.target} ...")
    raw = zap.alerts_for(args.target, args.category)
    print(f"    Raw alerts: {len(raw)} (source={'mock' if zap.used_mock else 'live ZAP'})")

    print(f"[2] Interpreting with {llm.backend} ...")
    findings = llm.interpret(args.category, args.target, raw)

    print(f"[3] Interpreted findings ({len(findings)}):")
    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
