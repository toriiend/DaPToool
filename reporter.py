from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, List

try:
    import markdown as mdlib
except Exception:
    mdlib = None

from ai_agent import AIResult


def _as_text(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    try:
        return json.dumps(x, indent=2, ensure_ascii=False)
    except Exception:
        return str(x)


def _format_owasp_mapping(mapping: Dict[str, str]) -> str:
    if not mapping:
        return "_(no mapping)_"
    lines = []
    for k in sorted(mapping.keys()):
        v = mapping.get(k, "")
        lines.append(f"- **{k}**: {v}")
    return "\n".join(lines)


def _build_cve_section(cve_enrichment: Dict[str, Any]) -> str:
    """
    NEW: Build CVE intelligence section
    """
    if not cve_enrichment:
        return ""
    
    summary = cve_enrichment.get("cve_summary", {})
    top_risks = summary.get("top_risks", [])
    attack_techniques = cve_enrichment.get("attack_techniques", {})
    
    lines = []
    lines.append("## 🔍 CVE Intelligence & Threat Analysis\n")
    
    # Summary stats
    lines.append("### Tổng quan CVE")
    lines.append(f"- **Tổng số CVE phát hiện**: {summary.get('total_cves_found', 0)}")
    lines.append(f"- **CVE có exploit công khai**: {summary.get('exploits_available', 0)}")
    
    sev = summary.get("severity_breakdown", {})
    lines.append(f"- **Phân bổ mức độ nghiêm trọng**:")
    lines.append(f"  -  CRITICAL: {sev.get('CRITICAL', 0)}")
    lines.append(f"  -  HIGH: {sev.get('HIGH', 0)}")
    lines.append(f"  -  MEDIUM: {sev.get('MEDIUM', 0)}")
    lines.append(f"  -  LOW: {sev.get('LOW', 0)}\n")
    
    # Top risks
    if top_risks:
        lines.append("###  Top 5 Rủi ro Ưu tiên")
        for i, risk in enumerate(top_risks, 1):
            lines.append(f"\n#### {i}. {risk.get('cve_id', 'Unknown')} "
                        f"[{risk.get('severity', 'UNKNOWN')}]")
            lines.append(f"- **Finding**: {risk.get('finding_title', 'N/A')}")
            lines.append(f"- **Risk Score**: {risk.get('risk_score', 0)}/20")
            lines.append(f"- **Exploit Available**: {'✓ Yes' if risk.get('exploit_available') else '✗ No'}")
            
            desc = risk.get('description', '')
            if desc:
                lines.append(f"- **Mô tả**: {desc}")
    
    # MITRE ATT&CK mapping
    if attack_techniques:
        lines.append("\n###  MITRE ATT&CK Techniques")
        for owasp, techniques in attack_techniques.items():
            lines.append(f"\n**{owasp}**:")
            for tech in techniques:
                lines.append(f"- {tech}")
    
    lines.append("")
    return "\n".join(lines)


def _build_attack_methods_section(enriched_findings: List[Dict[str, Any]]) -> str:
    """
    NEW: Build attack methods and defense strategies section
    """
    lines = []
    lines.append("##  Attack Vectors & Defense Strategies\n")
    
    # Collect unique attack methods
    all_attacks: Dict[str, Dict[str, Any]] = {}
    
    for finding in enriched_findings:
        methods = finding.get("attack_methods", [])
        for method in methods:
            name = method.get("name", "Unknown")
            if name not in all_attacks:
                all_attacks[name] = method
    
    if not all_attacks:
        lines.append("_Không có attack methods được xác định._\n")
        return "\n".join(lines)
    
    for attack_name, method in all_attacks.items():
        lines.append(f"### {attack_name}")
        lines.append(f"**Mô tả**: {method.get('description', 'N/A')}\n")
        
        # Detection methods
        detection = method.get("detection", [])
        if detection:
            lines.append("**Phương pháp phát hiện**:")
            for det in detection:
                lines.append(f"- {det}")
            lines.append("")
        
        # Mitigation
        mitigation = method.get("mitigation", [])
        if mitigation:
            lines.append("**Biện pháp khắc phục**:")
            for mit in mitigation:
                lines.append(f"- {mit}")
            lines.append("")
    
    return "\n".join(lines)


def _build_local_report(findings: Dict[str, Any]) -> str:
    t = findings.get("target", {})
    meta = findings.get("meta", {})
    items = findings.get("findings", [])
    cve_enrichment = findings.get("cve_enrichment", {})

    lines = []
    lines.append("#  Báo Cáo Đánh Giá An Ninh (Non-destructive)\n")
    lines.append(f"- **Thời gian**: {meta.get('generated_at','')}")
    lines.append(f"- **Chế độ**: {meta.get('mode','')}")
    lines.append(f"- **Target**: {t.get('raw','')} (host={t.get('host','')}, ip={t.get('ip','')})")
    lines.append(f"- **Evidence dir**: `evidence/`\n")
    
    # NEW: Add CVE section if available
    if cve_enrichment:
        lines.append(_build_cve_section(cve_enrichment))
    
    lines.append("## 🔎 Findings (Local Heuristics)\n")
    if not items:
        lines.append("_No heuristic findings produced. Check evidence outputs for details._\n")
    else:
        for i, f in enumerate(items, 1):
            sev = str(f.get('severity','info')).upper()
            sev_emoji = {"CRITICAL": "", "HIGH": "", "MEDIUM": "", "LOW": "", "INFO": "ℹ"}.get(sev, "ℹ")
            
            lines.append(f"### {i}. {sev_emoji} [{sev}] {f.get('title','')}")
            lines.append(f"- **OWASP**: {f.get('owasp','')}")
            lines.append(f"- **Evidence**: {f.get('evidence','')}")
            
            # NEW: Add CVE data if present
            cve_data = f.get("cve_data", [])
            if cve_data:
                lines.append(f"- **Related CVEs**:")
                for cve in cve_data[:3]:  # Show top 3
                    cve_id = cve.get('cve_id', 'Unknown')
                    cve_sev = cve.get('severity', 'UNKNOWN')
                    cve_desc = cve.get('description', 'N/A')[:150]
                    lines.append(f"  - **{cve_id}** [{cve_sev}]: {cve_desc}")
            
            # Enhanced remediation
            enhanced_rem = f.get("enhanced_remediation", "")
            if enhanced_rem:
                lines.append(f"- **Remediation**:\n{enhanced_rem}")
            else:
                lines.append(f"- **Remediation**: {f.get('remediation','')}")
            
            lines.append("")
    
    # NEW: Add attack methods section
    if items:
        lines.append(_build_attack_methods_section(items))
    
    lines.append("## 📊 Steps Executed\n")
    steps = findings.get("steps", {})
    for jid, sps in steps.items():
        lines.append(f"### {jid}")
        for s in sps:
            if s.get("skipped"):
                lines.append(f"- ⭕ {s.get('name')} (skipped: {s.get('skip_reason')})")
            else:
                of = s.get("output_file")
                of_rel = ""
                if of:
                    try:
                        of_rel = str(Path(of).relative_to(Path(findings.get("_run_dir", "."))))
                    except Exception:
                        of_rel = of
                lines.append(
                    f"- ✓ {s.get('name')} (rc={s.get('return_code')}, timeout={s.get('timeout_sec')}s)"
                    + (f" → `{of_rel}`" if of_rel else "")
                )
        lines.append("")

    lines.append("## ⚠️ Limitations\n")
    for lim in findings.get("limitations", []):
        lines.append(f"- {lim}")

    lines.append("\n## 📝 Notes\n")
    lines.append(
        "- This launcher is designed to be **safe**: no exploitation, no brute force. "
        "Use it for authorized assessments and still perform manual validation where needed."
    )
    
    return "\n".join(lines)


def export_reports(run_dir: str, findings: Dict[str, Any], ai_result: Optional[AIResult]) -> Dict[str, str]:
    run_path = Path(run_dir)
    rep_dir = run_path / "reports"
    rep_dir.mkdir(parents=True, exist_ok=True)

    findings["_run_dir"] = run_dir

    local_md = _build_local_report(findings)
    final_md = local_md

    if ai_result:
        final_md = (
            local_md
            + "\n\n---\n\n"
            + "# 🤖 AI Analysis\n\n"
            + f"- **Provider**: {ai_result.provider}\n"
            + f"- **Model**: {ai_result.model}\n\n"
            + "## Executive Summary\n\n"
            + _as_text(ai_result.summary)
            + "\n\n## OWASP Mapping\n\n"
            + _format_owasp_mapping(ai_result.owasp_mapping)
        )
        
        # NEW: Add CVE analysis if available
        if ai_result.cve_analysis:
            final_md += "\n\n## 🔐 CVE Analysis (AI-Enhanced)\n\n" + ai_result.cve_analysis
        
        # NEW: Add attack analysis if available
        if ai_result.attack_analysis:
            final_md += "\n\n## ⚔️ Attack Vector Analysis\n\n" + ai_result.attack_analysis
        
        final_md += (
            "\n\n## 🛠️ Remediation (Prioritized)\n\n"
            + _as_text(ai_result.remediation)
            + "\n\n## 📄 Full AI-Generated Report\n\n"
            + _as_text(ai_result.report_md)
        )

    md_path = rep_dir / "report.md"
    md_path.write_text(final_md, encoding="utf-8")

    # HTML
    if mdlib:
        html_body = mdlib.markdown(final_md, extensions=["tables", "fenced_code"])
    else:
        esc = (
            final_md.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        html_body = f"<pre>{esc}</pre>"

    html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Security Assessment Report with CVE Intelligence</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:1200px;margin:24px auto;padding:0 16px;line-height:1.6;background:#f5f5f5}}
.container{{background:white;padding:32px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.1)}}
code,pre{{background:#f6f8fa;padding:2px 6px;border-radius:4px;font-family:'Courier New',monospace}}
pre{{padding:16px;overflow:auto;border-left:4px solid #0366d6}}
h1,h2,h3{{line-height:1.2;color:#24292e}}
h1{{border-bottom:2px solid #0366d6;padding-bottom:12px}}
h2{{border-bottom:1px solid #e1e4e8;padding-bottom:8px;margin-top:32px}}
hr{{margin:32px 0;border:none;border-top:2px solid #e1e4e8}}
table{{border-collapse:collapse;width:100%;margin:16px 0}}
th,td{{border:1px solid #e1e4e8;padding:8px;text-align:left}}
th{{background:#f6f8fa}}
.severity-critical{{color:#d73a49;font-weight:bold}}
.severity-high{{color:#e36209;font-weight:bold}}
.severity-medium{{color:#ffd33d;font-weight:bold}}
.severity-low{{color:#28a745;font-weight:bold}}
</style>
</head>
<body>
<div class="container">
{html_body}
</div>
</body>
</html>"""
    html_path = rep_dir / "report.html"
    html_path.write_text(html, encoding="utf-8")

    return {"md": str(md_path), "html": str(html_path)}