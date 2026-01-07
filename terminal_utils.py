from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Optional


def _pick_terminal(choice: str) -> Optional[str]:
    if choice == "None (GUI only)":
        return None
    if choice != "Auto":
        return choice if shutil.which(choice) else None

    # Auto fallback order (Kali often has xfce4-terminal)
    for cand in ("xfce4-terminal", "gnome-terminal", "xterm"):
        if shutil.which(cand):
            return cand
    return None


def open_terminal_tail(terminal_choice: str, run_dir: str) -> None:
    """
    Opens a terminal that tails the run's evidence outputs.
    IMPORTANT: This does NOT run any scan command again, it only displays logs.
    """
    term = _pick_terminal(terminal_choice)
    if not term:
        return

    evidence_dir = Path(run_dir) / "evidence"
    cmd = f"cd {shlex.quote(str(evidence_dir))} && ls -la && echo '' && echo 'Tailing evidence files…' && tail -n +1 -f *.txt 2>/dev/null || tail -f /dev/null"

    if term == "xfce4-terminal":
        subprocess.Popen([term, "--title=SAL Evidence Tail", "--command", "bash", "-lc", cmd])
    elif term == "gnome-terminal":
        subprocess.Popen([term, "--title=SAL Evidence Tail", "--", "bash", "-lc", cmd])
    elif term == "xterm":
        subprocess.Popen([term, "-T", "SAL Evidence Tail", "-e", "bash", "-lc", cmd])
    else:
        # Unknown emulator style; best effort
        subprocess.Popen([term, "bash", "-lc", cmd])
