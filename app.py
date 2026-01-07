#!/usr/bin/env python3
from __future__ import annotations

import os
import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from orchestrator import Orchestrator, RunState

APP_TITLE = "DaPToool"


@dataclass
class UIConfig:
    jobs_path: str = "jobs.json"


class App(tk.Tk):
    def __init__(self, cfg: UIConfig) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1100x720")
        self.minsize(980, 650)

        self.orch = Orchestrator(jobs_path=cfg.jobs_path)

        self.target_var = tk.StringVar(value="")
        self.mode_var = tk.StringVar(value="Safe Passive")
        self.term_var = tk.StringVar(value="Auto")
        self.auth_var = tk.BooleanVar(value=False)

        self._build_ui()
        self._wire_events()

        try:
            self.jobs = self.orch.list_jobs()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load jobs.json:\n{e}")
            self.jobs = []

        self._render_owasp_buttons()

        self.after(120, self._drain_log_queue)
        self._refresh_controls()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Target (domain / URL / IP):").grid(row=0, column=0, sticky="w")
        target_entry = ttk.Entry(top, textvariable=self.target_var, width=65)
        target_entry.grid(row=0, column=1, sticky="we", padx=8)

        ttk.Label(top, text="Mode:").grid(row=0, column=2, sticky="e")
        mode = ttk.Combobox(
            top,
            textvariable=self.mode_var,
            values=["Safe Passive", "Extended (still non-destructive)"],
            state="readonly",
            width=28,
        )
        mode.grid(row=0, column=3, sticky="e", padx=(8, 0))

        ttk.Label(top, text="Terminal:").grid(row=1, column=2, sticky="e", pady=(8, 0))
        term = ttk.Combobox(
            top,
            textvariable=self.term_var,
            values=["Auto", "xfce4-terminal", "gnome-terminal", "xterm", "None (GUI only)"],
            state="readonly",
            width=28,
        )
        term.grid(row=1, column=3, sticky="e", padx=(8, 0), pady=(8, 0))

        auth = ttk.Checkbutton(
            top,
            text="CÓ QUYỀN CHƯA THẰNG CHÓ???",
            variable=self.auth_var,
        )
        auth.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))

        top.columnconfigure(1, weight=1)

        mid = ttk.Frame(self, padding=(10, 0, 10, 10))
        mid.pack(fill="both", expand=True)

        left = ttk.Frame(mid)
        left.pack(side="left", fill="both", expand=True)

        right = ttk.Frame(mid)
        right.pack(side="right", fill="y")

        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=(0, 8))

        self.run_btn = ttk.Button(btns, text="Run (All OWASP)", command=self._run_all)
        self.run_btn.pack(side="left")

        self.stop_btn = ttk.Button(btns, text="Stop", command=self._stop)
        self.stop_btn.pack(side="left", padx=8)

        self.clear_btn = ttk.Button(btns, text="Clear", command=self._clear_log)
        self.clear_btn.pack(side="left")

        self.export_btn = ttk.Button(btns, text="Export Report", command=self._export_report)
        self.export_btn.pack(side="left", padx=8)

        ttk.Label(left, text="Realtime log:").pack(anchor="w")
        self.log = ScrolledText(left, height=24, wrap="word")
        self.log.pack(fill="both", expand=True)
        self.log.configure(state="disabled")

        ttk.Label(right, text="OWASP Top 10:", font=("TkDefaultFont", 10, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        self.owasp_panel = ttk.Frame(right)
        self.owasp_panel.pack(fill="y", expand=False)

        self.status = tk.StringVar(value="Idle")
        statusbar = ttk.Label(self, textvariable=self.status, padding=(10, 6))
        statusbar.pack(fill="x", side="bottom")

    def _wire_events(self) -> None:
        self.auth_var.trace_add("write", lambda *_: self._refresh_controls())

    def _render_owasp_buttons(self) -> None:
        for child in self.owasp_panel.winfo_children():
            child.destroy()

        if not self.jobs:
            ttk.Label(self.owasp_panel, text="(No jobs loaded)").pack(anchor="w")
            return

        for job in self.jobs:
            b = ttk.Button(
                self.owasp_panel,
                text=f"{job['id']}  {job['title']}",
                width=42,
                command=lambda jid=job["id"]: self._run_one(jid),
            )
            b.pack(anchor="w", pady=3)

    def _append_log(self, line: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _drain_log_queue(self) -> None:
        while True:
            item = self.orch.try_pop_log()
            if item is None:
                break
            self._append_log(item)

        st = self.orch.state()
        self.status.set(st.human)
        self._refresh_controls()

        self.after(120, self._drain_log_queue)

    def _refresh_controls(self) -> None:
        st = self.orch.state()

        can_run = self.auth_var.get() and (st.state in (RunState.IDLE, RunState.DONE, RunState.ERROR))
        can_stop = st.state == RunState.RUNNING
        can_export = st.last_run_dir is not None and st.state != RunState.RUNNING

        self.run_btn.configure(state=("normal" if can_run else "disabled"))
        self.stop_btn.configure(state=("normal" if can_stop else "disabled"))
        self.export_btn.configure(state=("normal" if can_export else "disabled"))

    def _get_mode_key(self) -> str:
        return "safe" if self.mode_var.get().startswith("Safe") else "extended"

    def _get_terminal_choice(self) -> str:
        return self.term_var.get()

    def _guard_authorization(self) -> bool:
        if not self.auth_var.get():
            messagebox.showwarning("MÀY ĐÉO CÓ QUYỀN!!!", "XÁC NHẬN NHANH CON MẸ MÀY LÊN!!!")
            return False
        return True

    def _run_all(self) -> None:
        if not self._guard_authorization():
            return
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("HAHA THẰNG NGU", "QUÊN NHẬP TARGET KÌA TML!!!")
            return

        mode_key = self._get_mode_key()
        term_choice = self._get_terminal_choice()

        job_ids = [j["id"] for j in self.jobs]
        ok, msg = self.orch.start_run(target=target, mode=mode_key, job_ids=job_ids, terminal_choice=term_choice)
        if not ok:
            messagebox.showerror("Cannot start", msg)

    def _run_one(self, job_id: str) -> None:
        if not self._guard_authorization():
            return
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("HAHA THẰNG NGU", "QUÊN NHẬP TARGET KÌA TML!!!")
            return

        mode_key = self._get_mode_key()
        term_choice = self._get_terminal_choice()

        ok, msg = self.orch.start_run(target=target, mode=mode_key, job_ids=[job_id], terminal_choice=term_choice)
        if not ok:
            messagebox.showerror("Cannot start", msg)

    def _stop(self) -> None:
        self.orch.stop()

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _export_report(self) -> None:
        st = self.orch.state()
        if not st.last_run_dir:
            messagebox.showinfo("No run yet", "Run something first.")
            return

        ok, msg = self.orch.export_report(run_dir=st.last_run_dir)
        if ok:
            messagebox.showinfo("Report exported", msg)
        else:
            messagebox.showerror("Export failed", msg)

    def _on_close(self) -> None:
        try:
            self.orch.stop()
        except Exception:
            pass
        self.destroy()


def main() -> None:
    # NOTE:
    # - os.geteuid exists only on POSIX (Linux/Kali). Windows doesn't have it.
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pass

    cfg = UIConfig()
    app = App(cfg)
    app.mainloop()


if __name__ == "__main__":
    main()
