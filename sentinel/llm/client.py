"""LLM client: Claude-backed reasoning with a deterministic offline fallback.

When ANTHROPIC_API_KEY is set, the three reasoning steps (interpret / confirm /
report) are performed by claude-opus-5 with adaptive thinking. When it is not,
a deterministic heuristic performs the same steps so the whole pipeline still
runs end-to-end and produces a real report. The heuristic is intentionally
conservative and mirrors what the model is asked to do.
"""

from __future__ import annotations

import json
from typing import Any

from ..config import Settings
from . import prompts

# --- risk -> severity normalisation used by the heuristic and as a safety net ---
_RISK_TO_SEVERITY = {
    "informational": "informational",
    "info": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# Categories where a high-confidence, high-risk hit is treated as critical.
_CRITICAL_CATEGORIES = {"sqli"}


def _norm(value: str | None, default: str = "") -> str:
    return (value or default).strip()


class LLMClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._client = None
        self.backend = "heuristic"
        self.model = "n/a"
        # For OpenAI-compatible backends (Hugging Face, Ollama).
        self._chat_base = ""
        self._chat_key = ""

        provider = settings.llm_provider or "auto"

        def _try_claude() -> bool:
            if not settings.anthropic_api_key:
                return False
            try:
                import anthropic

                self._client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
                self.backend = "claude"
                self.model = settings.claude_model
                return True
            except Exception:
                self._client = None
                return False

        def _try_hf() -> bool:
            if not settings.hf_api_key:
                return False
            self.backend = "hf"
            self.model = settings.hf_model
            self._chat_base = settings.hf_base_url
            self._chat_key = settings.hf_api_key
            return True

        def _try_ollama() -> bool:
            # Local server; no API key required.
            self.backend = "ollama"
            self.model = settings.ollama_model
            self._chat_base = settings.ollama_base_url
            self._chat_key = "ollama"  # accepted-but-ignored dummy key
            return True

        if provider == "claude":
            _try_claude()
        elif provider == "hf":
            _try_hf()
        elif provider == "ollama":
            _try_ollama()
        elif provider == "heuristic":
            pass
        else:  # "auto": prefer Claude, then Hugging Face, then heuristic
            _try_claude() or _try_hf()

    # OpenAI-compatible backends share the same chat/JSON path.
    _OAI_BACKENDS = {"hf", "ollama"}

    # ------------------------------------------------------------------ Claude
    def _claude_json(
        self, system: str, user: str, schema: dict[str, Any], effort: str = "high"
    ) -> dict[str, Any]:
        """Single structured-output call. Returns the parsed object."""
        resp = self._client.messages.create(
            model=self.settings.claude_model,
            max_tokens=16000,
            thinking={"type": "adaptive"},
            output_config={
                "effort": effort,
                "format": {"type": "json_schema", "schema": schema},
            },
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = next((b.text for b in resp.content if b.type == "text"), "{}")
        return json.loads(text)

    # -------------------------------------------- OpenAI-compatible (HF/Ollama)
    def _oai_chat(self, system: str, user: str, max_tokens: int = 3000) -> str:
        """Call an OpenAI-compatible /chat/completions endpoint (HF or Ollama)."""
        import requests

        url = f"{self._chat_base.rstrip('/')}/chat/completions"
        resp = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {self._chat_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": 0.2,
                "max_tokens": max_tokens,
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    @staticmethod
    def _extract_json(text: str) -> Any:
        """Best-effort extraction of a JSON object/array from model text."""
        text = text.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text[4:]
        try:
            return json.loads(text)
        except Exception:
            pass
        # Scan for the first decodable JSON value.
        decoder = json.JSONDecoder()
        for i, ch in enumerate(text):
            if ch in "{[":
                try:
                    obj, _ = decoder.raw_decode(text[i:])
                    return obj
                except Exception:
                    continue
        return {}

    def _oai_json(self, system: str, user: str, max_tokens: int = 3000) -> Any:
        instruction = (
            "\n\nRespond with ONLY valid JSON — no prose, no markdown fences."
        )
        return self._extract_json(self._oai_chat(system, user + instruction, max_tokens))

    def _claude_text(self, system: str, user: str, effort: str = "high") -> str:
        resp = self._client.messages.create(
            model=self.settings.claude_model,
            max_tokens=16000,
            thinking={"type": "adaptive"},
            output_config={"effort": effort},
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in resp.content if b.type == "text")

    # -------------------------------------------------------------- interpret
    def interpret(
        self, category: str, target: str, raw_findings: list[dict]
    ) -> list[dict]:
        """Interpret raw tool output for one category into normalized findings."""
        if not raw_findings:
            return []
        if self.backend == "claude":
            try:
                return self._interpret_claude(category, target, raw_findings)
            except Exception:
                pass  # fall through to heuristic on any API/parse error
        elif self.backend in self._OAI_BACKENDS:
            try:
                return self._interpret_oai(category, target, raw_findings)
            except Exception:
                pass
        return self._interpret_heuristic(category, raw_findings)

    def _interpret_oai(
        self, category: str, target: str, raw_findings: list[dict]
    ) -> list[dict]:
        raw_json = json.dumps(raw_findings, indent=2)
        user = prompts.interpret_user_prompt(category, target, raw_json) + (
            '\n\nReturn a JSON object of the form {"findings": [ {"endpoint": str, '
            '"param": str, "name": str, "description": str, "evidence": str, '
            '"confidence": "low|medium|high", "remediation": str} ]}.'
        )
        out = self._oai_json(prompts.INTERPRET_SYSTEM, user)
        findings = out.get("findings", []) if isinstance(out, dict) else []
        for f in findings:
            f["category"] = category
            f["source"] = "nmap" if category == "recon" else "zap"
            f.setdefault("solution", f.get("remediation", ""))
        return findings

    def _interpret_claude(
        self, category: str, target: str, raw_findings: list[dict]
    ) -> list[dict]:
        schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "endpoint": {"type": "string"},
                            "param": {"type": "string"},
                            "name": {"type": "string"},
                            "description": {"type": "string"},
                            "evidence": {"type": "string"},
                            "confidence": {
                                "type": "string",
                                "enum": ["low", "medium", "high"],
                            },
                            "remediation": {"type": "string"},
                        },
                        "required": [
                            "endpoint",
                            "param",
                            "name",
                            "description",
                            "evidence",
                            "confidence",
                            "remediation",
                        ],
                    },
                }
            },
            "required": ["findings"],
        }
        raw_json = json.dumps(raw_findings, indent=2)
        out = self._claude_json(
            prompts.INTERPRET_SYSTEM,
            prompts.interpret_user_prompt(category, target, raw_json),
            schema,
            effort="medium",
        )
        findings = out.get("findings", [])
        for f in findings:
            f["category"] = category
            f["source"] = "nmap" if category == "recon" else "zap"
            f.setdefault("solution", f.get("remediation", ""))
        return findings

    def _interpret_heuristic(self, category: str, raw_findings: list[dict]) -> list[dict]:
        normalized: list[dict] = []
        for r in raw_findings:
            normalized.append(
                {
                    "category": category,
                    "endpoint": _norm(r.get("endpoint") or r.get("url") or r.get("uri")),
                    "param": _norm(r.get("param")),
                    "name": _norm(r.get("name") or r.get("alert"), "Unnamed finding"),
                    "description": _norm(r.get("description")),
                    "evidence": _norm(r.get("evidence")),
                    "remediation": _norm(r.get("solution") or r.get("remediation")),
                    "solution": _norm(r.get("solution") or r.get("remediation")),
                    "confidence": _norm(r.get("confidence"), "medium").lower() or "medium",
                    "risk": _norm(r.get("risk"), "medium").lower(),
                    "cweid": str(r.get("cweid", "")),
                    "source": "nmap" if category == "recon" else "zap",
                }
            )
        return normalized

    # ---------------------------------------------------------------- confirm
    def confirm(self, target: str, raw_results: dict[str, list]) -> list[dict]:
        if self.backend == "claude":
            try:
                return self._confirm_claude(target, raw_results)
            except Exception:
                pass
        elif self.backend in self._OAI_BACKENDS:
            try:
                return self._confirm_oai(target, raw_results)
            except Exception:
                pass
        return self._confirm_heuristic(raw_results)

    def _confirm_oai(self, target: str, raw_results: dict[str, list]) -> list[dict]:
        raw_json = json.dumps(raw_results, indent=2)
        user = prompts.confirm_user_prompt(target, raw_json) + (
            '\n\nReturn a JSON object of the form {"confirmed": [ {"category": str, '
            '"endpoint": str, "name": str, "severity": '
            '"informational|low|medium|high|critical", "confidence": '
            '"low|medium|high", "evidence": str, "description": str, '
            '"remediation": str, "false_positive": bool, "reasoning": str} ]}.'
        )
        out = self._oai_json(prompts.CONFIRM_SYSTEM, user, max_tokens=4000)
        confirmed = out.get("confirmed", []) if isinstance(out, dict) else []
        return confirmed if confirmed else self._confirm_heuristic(raw_results)

    def _confirm_claude(self, target: str, raw_results: dict[str, list]) -> list[dict]:
        schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "confirmed": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "category": {"type": "string"},
                            "endpoint": {"type": "string"},
                            "name": {"type": "string"},
                            "severity": {
                                "type": "string",
                                "enum": [
                                    "informational",
                                    "low",
                                    "medium",
                                    "high",
                                    "critical",
                                ],
                            },
                            "confidence": {
                                "type": "string",
                                "enum": ["low", "medium", "high"],
                            },
                            "evidence": {"type": "string"},
                            "description": {"type": "string"},
                            "remediation": {"type": "string"},
                            "false_positive": {"type": "boolean"},
                            "reasoning": {"type": "string"},
                        },
                        "required": [
                            "category",
                            "endpoint",
                            "name",
                            "severity",
                            "confidence",
                            "evidence",
                            "description",
                            "remediation",
                            "false_positive",
                            "reasoning",
                        ],
                    },
                }
            },
            "required": ["confirmed"],
        }
        raw_json = json.dumps(raw_results, indent=2)
        out = self._claude_json(
            prompts.CONFIRM_SYSTEM,
            prompts.confirm_user_prompt(target, raw_json),
            schema,
            effort="high",
        )
        return out.get("confirmed", [])

    def _confirm_heuristic(self, raw_results: dict[str, list]) -> list[dict]:
        seen: set[tuple] = set()
        confirmed: list[dict] = []
        for category, findings in raw_results.items():
            for f in findings:
                endpoint = _norm(f.get("endpoint"))
                name = _norm(f.get("name"), "Unnamed finding")
                key = (category, endpoint, name.lower())
                if key in seen:
                    continue
                seen.add(key)

                risk = _norm(f.get("risk"), "medium").lower()
                confidence = _norm(f.get("confidence"), "medium").lower()
                severity = _RISK_TO_SEVERITY.get(risk, "medium")

                # Drop obvious noise: informational + low confidence.
                is_noise = severity == "informational" and confidence == "low"

                # Escalate well-evidenced injection findings.
                if (
                    category in _CRITICAL_CATEGORIES
                    and severity == "high"
                    and confidence == "high"
                ):
                    severity = "critical"

                confirmed.append(
                    {
                        "category": category,
                        "endpoint": endpoint,
                        "name": name,
                        "severity": severity,
                        "confidence": confidence,
                        "evidence": _norm(f.get("evidence")),
                        "description": _norm(f.get("description")),
                        "remediation": _norm(f.get("remediation") or f.get("solution")),
                        "false_positive": is_noise,
                        "reasoning": (
                            "Discarded as low-confidence informational noise."
                            if is_noise
                            else "Evidence-backed; severity mapped from scanner risk."
                        ),
                    }
                )
        return confirmed

    # ----------------------------------------------------------------- report
    def write_report(
        self, target: str, confirmed: list[dict], meta: dict[str, Any]
    ) -> str:
        user = prompts.report_user_prompt(
            target, json.dumps(confirmed, indent=2), json.dumps(meta, indent=2)
        )
        if self.backend == "claude":
            try:
                return self._claude_text(prompts.REPORT_SYSTEM, user, effort="high")
            except Exception:
                pass
        elif self.backend in self._OAI_BACKENDS:
            try:
                text = self._oai_chat(prompts.REPORT_SYSTEM, user, max_tokens=4000)
                if text.strip():
                    return text
            except Exception:
                pass
        # Deterministic report is rendered by the reporting layer.
        from ..reporting.markdown import render_markdown

        return render_markdown(target, confirmed, meta)
