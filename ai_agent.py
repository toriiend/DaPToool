from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

# dotenv optional (để app vẫn chạy nếu bạn chưa cài python-dotenv)
try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass


@dataclass
class AIResult:
    provider: str
    model: str
    summary: str
    owasp_mapping: Dict[str, str]
    remediation: str
    report_md: str


def _env(name: str, default: str = "") -> str:
    v = os.getenv(name, default)
    return (v or "").strip().strip('"').strip("'")


def _get_provider() -> str:
    # Build 2.0 dùng AI_PROVIDER (recommended) :contentReference[oaicite:4]{index=4}
    p = _env("AI_PROVIDER", "gemini").lower()
    return p or "gemini"


def _get_api_key(provider: str) -> str:
    # Ưu tiên AI_API_KEY của build 2.0 :contentReference[oaicite:5]{index=5}
    key = _env("AI_API_KEY", "")
    if key:
        return key

    # Fallback provider-specific keys (để compatible build 1.0 / thói quen cũ)
    if provider == "gemini":
        return _env("GEMINI_API_KEY", "")
    if provider == "openai":
        return _env("OPENAI_API_KEY", "")
    if provider == "claude":
        return _env("CLAUDE_API_KEY", "")

    return ""


def _get_model(provider: str) -> str:
    # Build 2.0 dùng AI_MODEL :contentReference[oaicite:6]{index=6}
    m = _env("AI_MODEL", "")
    if m:
        return m

    # fallback provider-specific
    if provider == "gemini":
        return _env("GEMINI_MODEL", "gemini-2.5-flash")

    # default safe
    return "gemini-2.5-flash"


def _compact_findings(findings_json: Dict[str, Any], max_chars: int = 4500) -> str:
    """
    Giữ prompt gọn kiểu build 1.0 (thực dụng), nhưng input là findings.json của build 2.0.
    """
    tgt = findings_json.get("target", {}) or {}
    meta = findings_json.get("meta", {}) or {}
    findings = findings_json.get("findings", []) or []

    lines: list[str] = []
    lines.append(f"Target: {tgt.get('raw')} | host={tgt.get('host')} | ip={tgt.get('ip')} | url={tgt.get('url')}")
    lines.append(f"Mode: {meta.get('mode')} | Tools: {', '.join(meta.get('tools_present', []) or [])}")
    lines.append("")
    lines.append("Findings (heuristics/signals):")

    for i, f in enumerate(findings[:30], start=1):
        sev = (f.get("severity") or "info").upper()
        owasp = f.get("owasp") or "N/A"
        title = f.get("title") or "(no title)"
        evidence = (f.get("evidence") or "").strip()
        remediation = (f.get("remediation") or "").strip()

        if len(evidence) > 240:
            evidence = evidence[:240] + "…"
        if len(remediation) > 240:
            remediation = remediation[:240] + "…"

        lines.append(f"{i}. [{sev}] ({owasp}) {title}")
        if evidence:
            lines.append(f"   Evidence: {evidence}")
        if remediation:
            lines.append(f"   Local hint: {remediation}")

    text = "\n".join(lines)
    return text if len(text) <= max_chars else (text[:max_chars] + "\n…(truncated)")


def _extract_json_blob(text: str) -> Optional[Dict[str, Any]]:
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", (text or "").strip(), flags=re.IGNORECASE | re.MULTILINE)
    m = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def _fallback_mapping(findings_json: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, list[str]] = {}
    for f in (findings_json.get("findings") or []):
        code = f.get("owasp") or "N/A"
        out.setdefault(code, []).append(f.get("title") or "(no title)")
    return {k: "; ".join(v[:6]) for k, v in out.items()}


def analyze_findings(findings_json: Dict[str, Any]) -> AIResult:
    """
    Build 3.0 contract:
    - đọc env theo style build 2.0 (AI_PROVIDER/AI_API_KEY/AI_MODEL) :contentReference[oaicite:7]{index=7}
    - vẫn hỗ trợ GEMINI_API_KEY kiểu build 1.0
    - output AIResult ổn định cho reporter
    """
    provider = _get_provider()
    if provider != "gemini":
        # để dễ mở rộng sau: openai/claude/custom (nhưng 3.0 implement gemini trước cho chắc)
        raise RuntimeError(f"AI_PROVIDER='{provider}' not implemented yet. Use AI_PROVIDER=gemini for now.")

    api_key = _get_api_key(provider)
    if not api_key:
        raise RuntimeError("No API key found. Set AI_API_KEY (recommended) or GEMINI_API_KEY (fallback).")

    model_name = _get_model(provider)

    try:
        import google.generativeai as genai
    except Exception as e:
        raise RuntimeError(f"Missing dependency google-generativeai: {e}")

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(model_name)

    compact = _compact_findings(findings_json)

    # Prompt style: gọn + actionable như 1.0, nhưng trả về JSON để reporter ghép ổn định
    prompt = f"""
Bạn là Senior Security Engineer đang viết ghi chú đánh giá an ninh cho một bài kiểm tra ĐƯỢC ỦY QUYỀN và KHÔNG PHÁ HOẠI (non-destructive).

Ràng buộc bắt buộc:
- KHÔNG cung cấp exploit, payload, brute-force, hoặc hướng dẫn xâm nhập.
- Chỉ đưa ra khuyến nghị phòng thủ (defensive remediation).
- Viết ngắn gọn, thực tế, dễ triển khai.

Hãy trả về STRICT JSON với các khóa:
- summary: chuỗi (dạng bullet list, 3-6 ý)
- owasp_mapping: object ánh xạ mã OWASP -> giải thích 1-2 câu cho mỗi mã
- remediation: chuỗi (danh sách bullet theo mức ưu tiên)
- report_md: chuỗi (báo cáo Markdown với các mục: Trạng thái, Phát hiện chính, Ánh xạ OWASP, Khuyến nghị khắc phục, Bằng chứng/Bước tiếp theo)

Viết toàn bộ nội dung báo cáo bằng tiếng Việt (kể cả heading trong Markdown).

DATA:
{compact}
""".strip()

    try:
        resp = model.generate_content(
            prompt,
            generation_config={"temperature": 0.2},
        )
        text = getattr(resp, "text", "") or ""
    except Exception as e:
        raise RuntimeError(f"Gemini request failed: {e}")

    parsed = _extract_json_blob(text)
    if not parsed:
        # nếu model lỡ trả markdown thuần, vẫn không làm crash
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
