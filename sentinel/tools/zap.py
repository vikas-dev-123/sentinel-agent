"""OWASP ZAP wrapper.

Drives ZAP's REST API (spider + active scan + alerts) when a ZAP daemon is
reachable, and transparently falls back to bundled sample alerts when it is not
(or when mock mode is requested). One scan per target is cached and then sliced
per vulnerability category, so the four ZAP-backed agents don't each re-scan.

Corresponds to the `run_zap_active_scan` tool schema in the spec.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import requests

from ..config import Settings

_SAMPLE = Path(__file__).resolve().parents[2] / "sample_data" / "zap_alerts.json"

# CWE ids that strongly signal a category (used to classify real ZAP alerts).
_CWE_CATEGORY = {
    "89": "sqli",
    "79": "xss",
    "352": "auth",
    "1004": "auth",
    "384": "auth",
    "613": "auth",
}

_AUTH_KEYWORDS = ("cookie", "csrf", "session", "authentication", "login", "lockout")
_MISCONFIG_KEYWORDS = (
    "header",
    "directory",
    "browsing",
    "listing",
    "server leaks",
    "version",
    "disclosure",
    "cache",
    ".htaccess",
    "backup",
    "default",
)


def classify_alert(alert: dict) -> str:
    """Map a raw ZAP alert to one of the four ZAP categories."""
    if alert.get("sentinel_category"):
        return alert["sentinel_category"]

    cwe = str(alert.get("cweid", "")).strip()
    if cwe in _CWE_CATEGORY:
        return _CWE_CATEGORY[cwe]

    name = (alert.get("name") or alert.get("alert") or "").lower()
    if "sql injection" in name:
        return "sqli"
    if "cross site scripting" in name or "xss" in name:
        return "xss"
    if any(k in name for k in _AUTH_KEYWORDS):
        return "auth"
    return "misconfig"


def _normalize(alert: dict) -> dict:
    """Flatten a raw ZAP alert into the RawFinding shape agents consume."""
    return {
        "endpoint": alert.get("url") or alert.get("uri") or "",
        "param": alert.get("param", ""),
        "name": alert.get("name") or alert.get("alert") or "Unnamed alert",
        "description": alert.get("description", ""),
        "evidence": alert.get("evidence") or alert.get("attack") or "",
        "solution": alert.get("solution", ""),
        "risk": str(alert.get("risk", "")).lower(),
        "confidence": str(alert.get("confidence", "")).lower(),
        "cweid": str(alert.get("cweid", "")),
        "source": "zap",
    }


class ZapClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.base = settings.zap_api_url.rstrip("/")
        self.api_key = settings.zap_api_key
        self._cache: dict[str, list[dict]] = {}
        self.used_mock = False

    # ------------------------------------------------------------------ public
    def alerts_for(self, target: str, category: str) -> list[dict]:
        """Return normalized alerts for one category (running a scan if needed)."""
        alerts = self._ensure_scanned(target)
        return [_normalize(a) for a in alerts if classify_alert(a) == category]

    # --------------------------------------------------------------- scanning
    def _ensure_scanned(self, target: str) -> list[dict]:
        if target in self._cache:
            return self._cache[target]

        alerts: list[dict] | None = None
        if not self.settings.mock:
            try:
                alerts = self._live_scan(target)
            except Exception:
                alerts = None  # ZAP unreachable -> fall back to sample data

        if alerts is None:
            self.used_mock = True
            alerts = self._load_sample()

        self._cache[target] = alerts
        return alerts

    def _params(self, **kwargs) -> dict:
        params = {k: v for k, v in kwargs.items() if v is not None}
        if self.api_key:
            params["apikey"] = self.api_key
        return params

    def _get(self, view: str, **kwargs) -> dict:
        # ZAP actions like accessUrl fetch the target synchronously and can take
        # much longer than a plain API read, so use a generous timeout.
        url = f"{self.base}/JSON/{view}/"
        resp = requests.get(url, params=self._params(**kwargs), timeout=90)
        resp.raise_for_status()
        return resp.json()

    def _live_scan(self, target: str) -> list[dict]:
        # Access the target so it enters ZAP's site tree.
        self._get("core/action/accessUrl", url=target)

        # Spider to discover endpoints.
        spider_id = self._get("spider/action/scan", url=target).get("scan")
        self._wait("spider/view/status", spider_id, view_key="status")

        # Active scan for SQLi/XSS/misconfig rules.
        ascan_id = self._get("ascan/action/scan", url=target).get("scan")
        self._wait("ascan/view/status", ascan_id, view_key="status")

        data = self._get("core/view/alerts", baseurl=target)
        return data.get("alerts", [])

    def _wait(self, view: str, scan_id, view_key: str, timeout: int = 300) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self._get(view, scanId=scan_id).get(view_key, "0")
            if str(status) == "100":
                return
            time.sleep(2)

    # ----------------------------------------------------------------- sample
    @staticmethod
    def _load_sample() -> list[dict]:
        override = os.getenv("SENTINEL_ZAP_SAMPLE")
        path = Path(override) if override else _SAMPLE
        return json.loads(path.read_text(encoding="utf-8"))
