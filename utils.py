from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ParsedTarget:
    raw: str
    host: str
    ip: Optional[str]
    url: str
    port: Optional[int]


def _has_scheme(s: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", s))


def parse_target(target: str) -> ParsedTarget:
    """
    Accepts domain / IP / URL.
    Enforces: no whitespace, no shell-ish junk.
    """
    t = target.strip()
    if not t:
        raise ValueError("empty target")
    if any(ch.isspace() for ch in t):
        raise ValueError("target must not contain whitespace")
    if len(t) > 2048:
        raise ValueError("target too long")

    # URL
    if _has_scheme(t):
        from urllib.parse import urlparse

        u = urlparse(t)
        if not u.hostname:
            raise ValueError("invalid URL hostname")
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        ip = _resolve_ip(host)
        url = t
        return ParsedTarget(raw=t, host=host, ip=ip, url=url, port=port)

    # Domain or IP
    host = t
    port = None
    ip = None

    try:
        ipaddress.ip_address(host)
        ip = host
    except ValueError:
        ip = _resolve_ip(host)

    url = f"http://{host}/"
    return ParsedTarget(raw=t, host=host, ip=ip, url=url, port=port)


def _resolve_ip(host: str) -> Optional[str]:
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass
    return None


def ensure_output_dir() -> str:
    ts = time.strftime("%Y%m%d_%H%M%S")
    out = Path("output") / ts
    (out / "evidence").mkdir(parents=True, exist_ok=True)
    (out / "reports").mkdir(parents=True, exist_ok=True)
    (out / "meta").mkdir(parents=True, exist_ok=True)
    return str(out)


def safe_format_argv(argv_tmpl: List[str], ctx: Dict[str, str]) -> List[str]:
    """
    Formats argv template elements using str.format_map, but returns argv as a list
    for subprocess (NO shell=True).
    """
    out: List[str] = []
    for part in argv_tmpl:
        out.append(part.format_map(ctx))
    return out


def expand_pipelines(pipeline: List[Dict[str, Any]], pipelines: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Supports:
      {"ref": "base_web"} to include pipelines["base_web"] steps.
    """
    steps: List[Dict[str, Any]] = []
    for item in pipeline:
        if "ref" in item:
            ref = item["ref"]
            sub = pipelines.get(ref, [])
            if not isinstance(sub, list):
                raise ValueError(f"pipeline ref '{ref}' must be a list")
            steps.extend(sub)
        else:
            steps.append(item)
    return steps


@dataclass
class Tooling:
    present: set[str]

    @staticmethod
    def detect() -> "Tooling":
        candidates = [
            "ping",
            "nmap",
            "dig",
            "nslookup",
            "curl",
            "openssl",
            "tshark",
            "zap-baseline.py",
        ]
        present = {c for c in candidates if shutil.which(c)}
        return Tooling(present=present)


@dataclass
class Scope:
    allowed_hosts: List[str]
    allowed_cidrs: List[str]

    def is_allowed(self, host: str, ip: Optional[str]) -> bool:
        if not self.allowed_hosts and not self.allowed_cidrs:
            return True

        h = host.lower().rstrip(".")
        if any(_host_matches(h, rule) for rule in self.allowed_hosts):
            return True

        if ip:
            try:
                ip_obj = ipaddress.ip_address(ip)
                for cidr in self.allowed_cidrs:
                    if ip_obj in ipaddress.ip_network(cidr, strict=False):
                        return True
            except Exception:
                pass
        return False


def _host_matches(host: str, rule: str) -> bool:
    r = rule.lower().rstrip(".")
    if r == host:
        return True
    if r.startswith("*."):
        suffix = r[1:]
        return host.endswith(suffix)
    return False


def load_scope() -> Scope:
    p = Path("scope.json")
    if not p.exists():
        return Scope(allowed_hosts=[], allowed_cidrs=[])

    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
        return Scope(
            allowed_hosts=list(doc.get("allowed_hosts", [])),
            allowed_cidrs=list(doc.get("allowed_cidrs", [])),
        )
    except Exception:
        return Scope(allowed_hosts=["__invalid_scope_file__"], allowed_cidrs=[])
