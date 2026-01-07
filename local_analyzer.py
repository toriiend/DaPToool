from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils import ParsedTarget

SEC_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


@dataclass
class Finding:
    severity: str  # info/low/medium/high
    owasp: str
    title: str
    evidence: str
    remediation: str


def _read_text(p: Path) -> str:
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _parse_headers(raw: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for line in raw.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


def _missing_security_headers(headers: Dict[str, str]) -> List[str]:
    missing = []
    for h in SEC_HEADERS:
        if h not in headers:
            missing.append(h)
    return missing


def _server_version_signal(headers: Dict[str, str]) -> Optional[str]:
    return headers.get("server")


def _find_param_signals(html: str) -> List[str]:
    suspects = ["url=", "uri=", "dest=", "destination=", "next=", "continue=", "callback=", "return=", "redirect="]
    found = []
    low = html.lower()
    for s in suspects:
        if s in low:
            found.append(s.strip("="))
    return sorted(set(found))


def _ping_status(ping_out: str) -> Optional[str]:
    """
    Returns: "reachable" | "unreachable" | None
    - Linux ping: '0% packet loss'
    - Windows ping: 'Lost = 0'
    """
    if not ping_out.strip():
        return None

    low = ping_out.lower()

    # Reachable heuristics
    if "0% packet loss" in low:
        return "reachable"
    if "lost = 0" in low.replace(" ", ""):
        return "reachable"

    # Unreachable heuristics
    if "100% packet loss" in low:
        return "unreachable"
    if "destination host unreachable" in low:
        return "unreachable"
    if "request timed out" in low:
        return "unreachable"

    return None


def build_findings_json(
    run_dir: str,
    target: ParsedTarget,
    mode: str,
    step_results: Dict[str, List[Any]],
    tools_present: List[str],
) -> Dict[str, Any]:
    base = Path(run_dir) / "evidence"

    ping_raw = _read_text(base / "ping.txt")
    headers_raw = _read_text(base / "http_headers.txt")
    homepage = _read_text(base / "homepage_sample.txt")
    tls_raw = _read_text(base / "tls_s_client.txt")
    nmap_raw = _read_text(base / "nmap_top100.txt")

    headers = _parse_headers(headers_raw)
    findings: List[Finding] = []

    # Ping result (inventory / connectivity)
    ps = _ping_status(ping_raw)
    if ps == "reachable":
        findings.append(
            Finding(
                severity="info",
                owasp="A05",
                title="ICMP ping reachable (connectivity signal)",
                evidence="Ping succeeded (see evidence/ping.txt).",
                remediation="No action needed. If ICMP should be blocked, adjust network policy/ACLs accordingly.",
            )
        )
    elif ps == "unreachable":
        findings.append(
            Finding(
                severity="info",
                owasp="A05",
                title="ICMP ping not reachable (may be filtered or host down)",
                evidence="Ping failed or timed out (see evidence/ping.txt).",
                remediation="Not necessarily a security issue. Host may block ICMP; confirm reachability via TCP/HTTP checks.",
            )
        )

    # Missing security headers (signal)
    missing = _missing_security_headers(headers)
    if missing:
        findings.append(
            Finding(
                severity="low",
                owasp="A05",
                title="Missing common security headers (signal)",
                evidence=f"Missing: {', '.join(missing)}",
                remediation=(
                    "Set baseline headers where appropriate (CSP, HSTS for HTTPS, X-Content-Type-Options, "
                    "X-Frame-Options/Frame-Ancestors, Referrer-Policy, Permissions-Policy). "
                    "Validate with staging first to avoid breaking app behavior."
                ),
            )
        )

    # HSTS signal
    if "strict-transport-security" not in headers and target.url.startswith("https://"):
        findings.append(
            Finding(
                severity="low",
                owasp="A02",
                title="HSTS not observed on HTTPS target (signal)",
                evidence="Strict-Transport-Security header not found in response headers.",
                remediation="Enable HSTS after confirming HTTPS is enforced everywhere and subdomains are safe.",
            )
        )

    # Server banner
    server = _server_version_signal(headers)
    if server:
        findings.append(
            Finding(
                severity="info",
                owasp="A06",
                title="Server banner/version disclosed (signal)",
                evidence=f"Server: {server}",
                remediation="Consider minimizing version disclosure (server tokens) and ensure patch management is strong.",
            )
        )

    # DB error leakage signals (no payloads)
    sql_err = re.search(r"(sql syntax|mysql|postgresql|sqlite|odbc|jdbc|syntax error)", homepage, re.I)
    if sql_err:
        findings.append(
            Finding(
                severity="medium",
                owasp="A03",
                title="Potential DB error leakage in response (signal)",
                evidence=f"Matched: {sql_err.group(0)}",
                remediation="Ensure errors are handled and generic messages returned; log details server-side only.",
            )
        )

    # Stack trace signal
    stack = re.search(r"(Exception|Traceback \(most recent call last\)|Stack trace)", homepage, re.I)
    if stack:
        findings.append(
            Finding(
                severity="low",
                owasp="A09",
                title="Potential verbose error/stack trace exposure (signal)",
                evidence=f"Matched: {stack.group(0)}",
                remediation="Disable debug error pages in production; ensure structured logging and monitoring are enabled.",
            )
        )

    # SSRF-ish params (passive)
    params = _find_param_signals(homepage)
    if params:
        findings.append(
            Finding(
                severity="info",
                owasp="A10",
                title="SSRF/Open-Redirect related parameter names observed (passive signal)",
                evidence=f"Observed in HTML: {', '.join(params)}",
                remediation=(
                    "Review endpoints that accept URLs/hosts. Apply allowlists, URL parsing hardening, "
                    "and block access to internal IP ranges/metadata services."
                ),
            )
        )

    # Open ports inventory
    if nmap_raw.strip():
        findings.append(
            Finding(
                severity="info",
                owasp="A05",
                title="Open ports discovered (inventory)",
                evidence="See evidence/nmap_top100.txt",
                remediation="Validate exposed services are intended; minimize attack surface; enforce network ACLs.",
            )
        )

    # TLS evidence
    if tls_raw.strip():
        findings.append(
            Finding(
                severity="info",
                owasp="A02",
                title="TLS handshake/cert evidence captured (extended)",
                evidence="See evidence/tls_s_client.txt",
                remediation="Review protocol/cipher policy, certificate chain, expiry, and OCSP stapling if applicable.",
            )
        )

    doc = {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mode": mode,
            "tools_present": tools_present,
        },
        "target": {
            "raw": target.raw,
            "host": target.host,
            "ip": target.ip,
            "url": target.url,
            "port": target.port,
        },
        "steps": {
            jid: [
                {
                    "name": s.name,
                    "argv": s.argv,
                    "timeout_sec": s.timeout_sec,
                    "started_at": s.started_at,
                    "ended_at": s.ended_at,
                    "return_code": s.return_code,
                    "skipped": s.skipped,
                    "skip_reason": s.skip_reason,
                    "output_file": s.output_file,
                }
                for s in steps
            ]
            for jid, steps in step_results.items()
        },
        "findings": [asdict(f) for f in findings],
        "limitations": [
            "This launcher is intentionally non-destructive and does not automate exploitation or brute force.",
            "OWASP Top 10 coverage cannot be 100% automated (auth flows, business logic, and design issues require manual review).",
        ],
    }
    return doc
