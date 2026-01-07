# Security Assessment Launcher (Kali Linux) — Authorized Use Only

A Python 3 + Tkinter GUI that launches **non-destructive** security assessment pipelines mapped to OWASP Top 10.
No exploitation, no brute force. This is meant for **authorized** pentests / internal assessments.

## What it does
- GUI buttons for OWASP Top 10 categories
- Runs safe commands (rate-limited, timeouts, scope guard)
- Streams realtime logs in GUI (scrollable)
- Optional terminal viewer that **tails evidence files** (does not re-run scans)
- Saves all outputs to `output/<timestamp>/`
- Optional AI Agent analysis to summarize + map OWASP + remediation + Markdown/HTML report

## Safety / Legal guardrails
- UI has a required checkbox: **"I have authorization"**
- Commands are executed with `subprocess.Popen(argv_list)` **without** `shell=True`
- Per-step **timeout** + soft delay between steps
- Scope guard:
  - Default: commands only target the exact host/IP you typed (no wide scanning)
  - Optional `scope.json`: deny runs if target is out-of-scope

## Dependencies (optional, tool will detect missing ones)
Install what you need on Kali:
```bash
sudo apt update
sudo apt install -y curl dnsutils nmap openssl
# Optional:
sudo apt install -y tshark
# Optional ZAP baseline script (varies by Kali version/packages):
sudo apt install -y zaproxy
