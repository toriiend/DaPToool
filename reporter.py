from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

# markdown optional: không có lib vẫn export html fallback
try:
    import markdown as mdlib
except Exception:
    mdlib = None  # type: ignore

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


def _build_local_report(findings: Dict[str, Any]) -> str:
    t = findings.get("target", {})
    meta = findings.get("meta", {})
    items = findings.get("findings", [])

    lines = []
    lines.append("# Security Assessment Report (Non-destructive)\n")
    lines.append(f"- Generated: **{meta.get('generated_at','')}**")
    lines.append(f"- Mode: **{meta.get('mode','')}**")
    lines.append(f"- Target: **{t.get('raw','')}** (host={t.get('host','')}, ip={t.get('ip','')})")
    lines.append("- Evidence dir: `evidence/`\n")

    lines.append("## Findings (local heuristics)\n")
    if not items:
        lines.append("_No heuristic findings produced. Check evidence outputs for details._\n")
    else:
        for i, f in enumerate(items, 1):
            lines.append(f"### {i}. [{str(f.get('severity','info')).upper()}] {f.get('title','')}")
            lines.append(f"- OWASP: **{f.get('owasp','')}**")
            lines.append(f"- Evidence: {f.get('evidence','')}")
            lines.append(f"- Remediation: {f.get('remediation','')}\n")

    lines.append("## Steps executed\n")
    steps = findings.get("steps", {})
    for jid, sps in steps.items():
        lines.append(f"### {jid}")
        for s in sps:
            if s.get("skipped"):
                lines.append(f"- ⏭ {s.get('name')} (skipped: {s.get('skip_reason')})")
            else:
                of = s.get("output_file")
                of_rel = ""
                if of:
                    try:
                        of_rel = str(Path(of).relative_to(Path(findings.get("_run_dir", "."))))
                    except Exception:
                        of_rel = of
                lines.append(
                    f"-  {s.get('name')} (rc={s.get('return_code')}, timeout={s.get('timeout_sec')}s)"
                    + (f" → `{of_rel}`" if of_rel else "")
                )
        lines.append("")

    lines.append("## Limitations\n")
    for lim in findings.get("limitations", []):
        lines.append(f"- {lim}")

    lines.append("\n## Notes\n")
    lines.append(
        "- This launcher is designed to be **safe**: no exploitation, no brute force. "
        "Use it for authorized assessments and still perform manual validation where needed."
    )
    return "\n".join(lines)


def export_reports(run_dir: str, findings: Dict[str, Any], ai_result: Optional[AIResult]) -> Dict[str, str]:
    run_path = Path(run_dir)
    rep_dir = run_path / "reports"
    rep_dir.mkdir(parents=True, exist_ok=True)

    findings["_run_dir"] = run_dir  # best effort for relative paths

    local_md = _build_local_report(findings)
    final_md = local_md

    if ai_result:
        final_md = (
            local_md
            + "\n\n---\n\n"
            + "# AI Analysis\n\n"
            + f"- Provider: **{ai_result.provider}**\n"
            + f"- Model: **{ai_result.model}**\n\n"
            + "## Executive summary\n\n"
            + _as_text(ai_result.summary)
            + "\n\n## OWASP mapping\n\n"
            + _format_owasp_mapping(ai_result.owasp_mapping)
            + "\n\n## Remediation (prioritized)\n\n"
            + _as_text(ai_result.remediation)
            + "\n\n## Full AI-generated report\n\n"
            + _as_text(ai_result.report_md)
        )

    md_path = rep_dir / "report.md"
    md_path.write_text(final_md, encoding="utf-8")

    # HTML
    if mdlib:
        html_body = mdlib.markdown(final_md, extensions=["tables", "fenced_code"])
    else:
        # fallback HTML (no dependency)
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
<title>Security Assessment Report</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;line-height:1.5}}
code,pre{{background:#f6f8fa;padding:2px 6px;border-radius:6px}}
pre{{padding:12px;overflow:auto}}
h1,h2,h3{{line-height:1.2}}
hr{{margin:24px 0}}
</style>
</head>
<body>
{html_body}
</body>
</html>"""
    html_path = rep_dir / "report.html"
    html_path.write_text(html, encoding="utf-8")

    return {"md": str(md_path), "html": str(html_path)}
