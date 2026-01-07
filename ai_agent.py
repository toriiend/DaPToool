from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    # dotenv is optional; env vars may be provided by OS
    pass


@dataclass
class AIResult:
    provider: str
    model: str
    summary: str
    owasp_mapping: Dict[str, str]
    remediation: str
    report_md: str


def _compact_findings(findings_json: Dict[str, Any], max_chars: int = 6000) -> str:
    """
    Build a compact plaintext snapshot from findings.json to keep prompts small.
    """
    tgt = findings_json.get("target", {}) or {}
    meta = findings_json.get("meta", {}) or {}
    findings = findings_json.get("findings", []) or []

    lines = []
    lines.append(f"Target: {tgt.get('raw')} | host={tgt.get('host')} | ip={tgt.get('ip')} | url={tgt.get('url')}")
    lines.append(f"Mode: {meta.get('mode')} | Tools: {', '.join(meta.get('tools_present', []) or [])}")
    lines.append("")
    lines.append("Findings (signals / evidence):")

    for i, f in enumerate(findings, start=1):
        sev = (f.get("severity") or "info").upper()
        owasp = f.get("owasp") or "N/A"
        title = f.get("title") or "(no title)"
        evidence = (f.get("evidence") or "").strip()
        remediation = (f.get("remediation") or "").strip()

        # keep each item short
        if len(evidence) > 220:
            evidence = evidence[:220] + "…"
        if len(remediation) > 220:
            remediation = remediation[:220] + "…"

        lines.append(f"{i}. [{sev}] ({owasp}) {title}")
        if evidence:
            lines.append(f"   Evidence: {evidence}")
        if remediation:
            lines.append(f"   Suggested fix: {remediation}")

    text = "\n".join(lines)
    if len(text) > max_chars:
        return text[:max_chars] + "\n…(truncated)"
    return text


def _fallback_mapping(findings_json: Dict[str, Any]) -> Dict[str, str]:
    """
    If LLM is unavailable, at least group findings by OWASP code.
    """
    out: Dict[str, list[str]] = {}
    for f in (findings_json.get("findings") or []):
        code = f.get("owasp") or "N/A"
        out.setdefault(code, []).append(f.get("title") or "(no title)")
    return {k: "; ".join(v[:6]) for k, v in out.items()}


def _extract_json_blob(text: str) -> Optional[Dict[str, Any]]:
    """
    Try to extract a JSON object from model output (even if wrapped in markdown fences).
    """
    # remove code fences if any
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.IGNORECASE | re.MULTILINE)

    # find first {...} block
    m = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not m:
        return None
    blob = m.group(0)
    try:
        return json.loads(blob)
    except Exception:
        return None


def analyze_findings(findings_json: Dict[str, Any]) -> AIResult:
    """
    Build expects: analyze_findings(findings_json) -> AIResult-like object.
    If no API key / missing dependency, raises RuntimeError (caller can catch and disable AI).
    """
    api_key = os.getenv("GEMINI_API_KEY")
    model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not set (AI disabled).")

    try:
        import google.generativeai as genai
    except Exception as e:
        raise RuntimeError(f"google-generativeai not installed ({e}).")

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(model_name)

    compact = _compact_findings(findings_json)

    prompt = f"""
You are a Security Auditor working on an AUTHORIZED security assessment.
Constraints:
- Non-destructive. No exploitation, no brute force, no payload crafting.
- Be practical, use best practices, and keep it readable.

Input is a compact summary of scanner outputs + heuristics.

RETURN STRICT JSON with keys:
- summary: string (3-6 bullet points, concise)
- owasp_mapping: object mapping OWASP codes -> short explanation (1-2 lines each)
- remediation: string (prioritized remediation bullets)
- report_md: string (a clean Markdown report with headings)

DATA:
{compact}
""".strip()

    try:
        resp = model.generate_content(prompt)
        text = getattr(resp, "text", "") or ""
    except Exception as e:
        raise RuntimeError(f"Gemini request failed: {e}")

    parsed = _extract_json_blob(text)
    if not parsed:
        # fallback: still produce something usable
        return AIResult(
            provider="gemini",
            model=model_name,
            summary="(AI output not in JSON) See report_md.",
            owasp_mapping=_fallback_mapping(findings_json),
            remediation="(AI output not in JSON) See report_md.",
            report_md=text.strip() or "(empty AI response)",
        )

    return AIResult(
        provider="gemini",
        model=model_name,
        summary=str(parsed.get("summary") or "").strip(),
        owasp_mapping=dict(parsed.get("owasp_mapping") or {}),
        remediation=str(parsed.get("remediation") or "").strip(),
        report_md=str(parsed.get("report_md") or "").strip(),
    )
