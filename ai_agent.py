from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

# dotenv optional
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

import requests

def fetch_cve_data(cve_id):
    """
    Lấy thông tin CVE từ kho dữ liệu của CIRCL (Computer Incident Response Center Luxembourg).
    Nguồn này cực uy tín, free, không cần API Key, update cực nhanh.
    """
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if not data: # Đôi khi trả về 200 nhưng null
                return None
            
            # Lọc bớt rác, chỉ lấy cái quan trọng để tiết kiệm token cho AI
            summary = {
                "id": data.get("id"),
                "cvss": data.get("cvss"),
                "summary": data.get("summary"),
                "references": data.get("references", [])[:3], # Lấy 3 link tham khảo
                "published": data.get("Published"),
                "vulnerable_configuration": data.get("vulnerable_configuration", [])[:5]
            }
            return summary
        else:
            return None
    except Exception as e:
        print(f"[!] Error fetching CVE: {e}")
        return None
    


@dataclass
class AIResult:
    provider: str
    model: str
    summary: str
    owasp_mapping: Dict[str, str]
    remediation: str
    report_md: str
    cve_analysis: Optional[str] = None  # NEW: CVE-specific analysis
    attack_analysis: Optional[str] = None  # NEW: Attack method analysis


def _env(name: str, default: str = "") -> str:
    v = os.getenv(name, default)
    return (v or "").strip().strip('"').strip("'")


def _get_provider() -> str:
    p = _env("AI_PROVIDER", "gemini").lower()
    return p or "gemini"


def _get_api_key(provider: str) -> str:
    key = _env("AI_API_KEY", "")
    if key:
        return key

    if provider == "gemini":
        return _env("GEMINI_API_KEY", "")
    if provider == "openai":
        return _env("OPENAI_API_KEY", "")
    if provider == "claude":
        return _env("CLAUDE_API_KEY", "")

    return ""


def _get_model(provider: str) -> str:
    m = _env("AI_MODEL", "")
    if m:
        return m

    if provider == "gemini":
        return _env("GEMINI_MODEL", "gemini-2.0-flash-exp")

    return "gemini-2.0-flash-exp"


def _compact_findings(findings_json: Dict[str, Any], max_chars: int = 6000) -> str:
    """
    Enhanced version with CVE data
    """
    tgt = findings_json.get("target", {}) or {}
    meta = findings_json.get("meta", {}) or {}
    findings = findings_json.get("findings", []) or []
    cve_summary = findings_json.get("cve_enrichment", {}).get("cve_summary", {})

    lines: list[str] = []
    lines.append(f"Target: {tgt.get('raw')} | host={tgt.get('host')} | ip={tgt.get('ip')} | url={tgt.get('url')}")
    lines.append(f"Mode: {meta.get('mode')} | Tools: {', '.join(meta.get('tools_present', []) or [])}")
    
    # Add CVE summary if available
    if cve_summary:
        lines.append(f"\nCVE Intelligence Summary:")
        lines.append(f"- Total CVEs: {cve_summary.get('total_cves_found', 0)}")
        lines.append(f"- Exploits Available: {cve_summary.get('exploits_available', 0)}")
        sev = cve_summary.get('severity_breakdown', {})
        lines.append(f"- Severity: CRITICAL={sev.get('CRITICAL',0)}, HIGH={sev.get('HIGH',0)}, MEDIUM={sev.get('MEDIUM',0)}, LOW={sev.get('LOW',0)}")
    
    lines.append("\nFindings (with CVE & attack intelligence):")

    for i, f in enumerate(findings[:30], start=1):
        sev = (f.get("severity") or "info").upper()
        owasp = f.get("owasp") or "N/A"
        title = f.get("title") or "(no title)"
        evidence = (f.get("evidence") or "").strip()
        
        # Include CVE data if present
        cve_data = f.get("cve_data", [])
        attack_methods = f.get("attack_methods", [])
        
        if len(evidence) > 240:
            evidence = evidence[:240] + "…"

        lines.append(f"{i}. [{sev}] ({owasp}) {title}")
        if evidence:
            lines.append(f"   Evidence: {evidence}")
        
        # Add CVE info
        if cve_data:
            lines.append(f"   CVEs: {len(cve_data)} related")
            for cve in cve_data[:2]:  # Show top 2
                cve_id = cve.get('cve_id', 'Unknown')
                cve_sev = cve.get('severity', 'UNKNOWN')
                lines.append(f"     - {cve_id} [{cve_sev}]")
        
        # Add attack methods
        if attack_methods:
            lines.append(f"   Attack vectors: {len(attack_methods)} identified")

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
    Enhanced version with CVE and attack method context
    """
    provider = _get_provider()
    if provider != "gemini":
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

    # Enhanced prompt with CVE context
    prompt = f"""
Bạn là Senior Security Engineer đang viết báo cáo đánh giá an ninh chi tiết cho một bài kiểm tra ĐÃ ĐƯỢC ỦY QUYỀN và KHÔNG PHÁ HOẠI (non-destructive).

Rằng buộc bắt buộc:
- KHÔNG cung cấp exploit code, payload, brute-force scripts, hoặc hướng dẫn xâm nhập chi tiết.
- Chỉ đưa ra khuyến nghị phòng thủ (defensive remediation) và phương pháp phát hiện.
- Phân tích CVE và attack methods để đưa ra đánh giá rủi ro thực tế.
- Viết ngắn gọn, thực tế, dễ triển khai.

Context: Dữ liệu đã được làm giàu với CVE intelligence và attack method mapping từ MITRE ATT&CK framework.

Hãy trả về STRICT JSON với các khóa:
- summary: chuỗi (dạng bullet list, 4-7 ý chính bao gồm đánh giá CVE nếu có)
- owasp_mapping: object ánh xạ mã OWASP -> giải thích 1-2 câu cho mỗi mã, bao gồm CVE liên quan nếu có
- remediation: chuỗi (danh sách bullet theo mức ưu tiên, tham chiếu CVE cụ thể nếu có)
- cve_analysis: chuỗi (phân tích tổng quan về CVE findings, exploitability, risk level - để trống nếu không có CVE data)
- attack_analysis: chuỗi (phân tích các attack vectors có thể, detection methods, và mitigation strategies)
- report_md: chuỗi (báo cáo Markdown đầy đủ với các mục: 
    * Trạng thái Tổng quan
    * Phát hiện Chính & CVE Analysis
    * Ánh xạ OWASP Top 10
    * Attack Vectors & Techniques
    * Khuyến nghị Khắc phục (ưu tiên theo severity)
    * Bằng chứng/Bước tiếp theo)

Viết toàn bộ nội dung báo cáo bằng tiếng Việt (kể cả heading trong Markdown).
Với CVE data, cung cấp risk assessment cụ thể và prioritization rõ ràng.



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
        return AIResult(
            provider="gemini",
            model=model_name,
            summary="(AI output not in JSON) See report_md.",
            owasp_mapping=_fallback_mapping(findings_json),
            remediation="(AI output not in JSON) See report_md.",
            report_md=text.strip() or "(empty AI response)",
            cve_analysis=None,
            attack_analysis=None
        )

    return AIResult(
        provider="gemini",
        model=model_name,
        summary=str(parsed.get("summary") or "").strip(),
        owasp_mapping=dict(parsed.get("owasp_mapping") or {}),
        remediation=str(parsed.get("remediation") or "").strip(),
        report_md=str(parsed.get("report_md") or "").strip(),
        cve_analysis=str(parsed.get("cve_analysis") or "").strip() or None,
        attack_analysis=str(parsed.get("attack_analysis") or "").strip() or None
    )

def analyze_cve(self, cve_id):
        # BƯỚC 1: Code lấy dữ liệu thật (Grounding)
        cve_data = fetch_cve_data(cve_id)
        
        if not cve_data:
            return f"Không tìm thấy thông tin về {cve_id} (hoặc lỗi kết nối)."

        # BƯỚC 2: AI phân tích dựa trên dữ liệu thật
        prompt = f"""
        Role: Security Researcher.
        Task: Explain this CVE and suggest remediation.
        
        REAL DATA from Database:
        {cve_data}
        
        OUTPUT FORMAT:
        **Summary:** (Simple explanation of the bug)
        **Severity:** (Based on CVSS)
        **Impact:** (What happens if exploited?)
        **Remediation:** (Step-by-step fix)
        **MITRE Mapping:** (Map to ATT&CK Technique ID if possible)
        """
        
        # Gọi model.generate_content(prompt)...