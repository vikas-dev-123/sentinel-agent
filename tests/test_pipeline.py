"""End-to-end pipeline tests (offline / mock mode).

These run without ZAP, Nmap, or an API key — they exercise the full LangGraph
graph over bundled sample data with the deterministic heuristic backend.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.config import ScopeError, Settings, assert_in_scope  # noqa: E402
from sentinel.orchestrator import run_scan  # noqa: E402


@pytest.fixture
def mock_settings(tmp_path) -> Settings:
    s = Settings()
    s.mock = True
    s.anthropic_api_key = None  # force heuristic backend for deterministic tests
    s.reports_dir = str(tmp_path / "reports")
    return s


def test_full_pipeline_produces_findings_and_report(mock_settings):
    state = run_scan("http://localhost/dvwa", mock_settings)

    assert state["status"] == "done"
    # All six category channels populated.
    for cat in ("recon", "sqli", "xss", "auth", "misconfig"):
        assert cat in state["raw_results"]

    confirmed = [f for f in state["confirmed_findings"] if not f.get("false_positive")]
    assert confirmed, "expected at least one confirmed finding"

    # SQLi high+high should be escalated to critical by the heuristic.
    sqli = [f for f in confirmed if f["category"] == "sqli"]
    assert any(f["severity"] == "critical" for f in sqli)

    # Report artifacts exist on disk.
    assert Path(state["report_path"]).exists()
    assert "# Penetration Test Report" in state["report_markdown"]


def test_informational_noise_is_filtered(mock_settings):
    state = run_scan("http://localhost/dvwa", mock_settings)
    confirmed = state["confirmed_findings"]
    # The Unix timestamp disclosure (informational + low confidence) is discarded.
    ts = [f for f in confirmed if "Timestamp" in f.get("name", "")]
    assert ts and ts[0]["false_positive"] is True


def test_scope_enforcement_blocks_remote_target():
    s = Settings()
    with pytest.raises(ScopeError):
        assert_in_scope("http://example.com", s)


def test_scope_allows_localhost():
    s = Settings()
    assert assert_in_scope("http://localhost/dvwa", s) == "localhost"


def test_allow_any_override():
    s = Settings()
    s.allow_any_target = True
    assert assert_in_scope("http://example.com", s) == "example.com"
