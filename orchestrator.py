from __future__ import annotations

import json
import os
import queue
import signal
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ai_agent import analyze_findings
from local_analyzer import build_findings_json
from reporter import export_reports
from terminal_utils import open_terminal_tail
from utils import (
    Tooling,
    ensure_output_dir,
    expand_pipelines,
    load_scope,
    parse_target,
    safe_format_argv,
)


class RunState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"


@dataclass
class OrchestratorState:
    state: RunState = RunState.IDLE
    human: str = "Idle"
    last_run_dir: Optional[str] = None
    active_job: Optional[str] = None


@dataclass
class StepResult:
    name: str
    argv: List[str]
    timeout_sec: int
    started_at: float
    ended_at: float
    return_code: Optional[int]
    skipped: bool
    skip_reason: Optional[str]
    output_file: Optional[str]


class Orchestrator:
    def __init__(self, jobs_path: str = "jobs.json") -> None:
        self.jobs_path = jobs_path
        self._log_q: "queue.Queue[str]" = queue.Queue()
        self._state = OrchestratorState()

        self._stop_evt = threading.Event()
        self._worker: Optional[threading.Thread] = None

        self._current_pgid: Optional[int] = None  # POSIX only
        self._current_proc: Any = None            # cross-platform fallback
        self._lock = threading.Lock()

        self._jobs_doc = self._load_jobs_doc()

    def _load_jobs_doc(self) -> Dict[str, Any]:
        with open(self.jobs_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def list_jobs(self) -> List[Dict[str, Any]]:
        jobs = self._jobs_doc.get("jobs", [])
        return [{"id": j["id"], "title": j["title"]} for j in jobs]

    def try_pop_log(self) -> Optional[str]:
        try:
            return self._log_q.get_nowait()
        except queue.Empty:
            return None

    def state(self) -> OrchestratorState:
        with self._lock:
            return OrchestratorState(**self._state.__dict__)

    def _set_state(self, **kwargs: Any) -> None:
        with self._lock:
            for k, v in kwargs.items():
                setattr(self._state, k, v)

    def log(self, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self._log_q.put(f"[{ts}] {msg}")

    def start_run(self, target: str, mode: str, job_ids: List[str], terminal_choice: str) -> Tuple[bool, str]:
        st = self.state()
        if st.state == RunState.RUNNING:
            return False, "Already running."

        try:
            t = parse_target(target)
        except Exception as e:
            return False, f"Invalid target: {e}"

        scope = load_scope()
        if not scope.is_allowed(t.host, t.ip):
            return False, (
                "Target is out-of-scope by scope.json rules.\n"
                "Edit scope.json (or delete it) to control allowed hosts/CIDRs."
            )

        run_dir = ensure_output_dir()
        self._set_state(state=RunState.RUNNING, human=f"Running → {', '.join(job_ids)}", last_run_dir=run_dir)
        self._stop_evt.clear()

        self._worker = threading.Thread(
            target=self._worker_main,
            args=(t, mode, job_ids, terminal_choice, run_dir),
            daemon=True,
        )
        self._worker.start()
        return True, f"Started. Output: {run_dir}"

    def stop(self) -> None:
        import subprocess

        self._stop_evt.set()
        self.log("Stop requested. Terminating active process group (if any)…")

        with self._lock:
            pgid = self._current_pgid
            proc = self._current_proc

        if os.name == "posix" and pgid:
            try:
                os.killpg(pgid, signal.SIGTERM)
                time.sleep(0.6)
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception as e:
                self.log(f"Warning: failed to kill process group: {e}")
            return

        if proc:
            try:
                if os.name == "nt":
                    try:
                        proc.send_signal(signal.CTRL_BREAK_EVENT)
                        time.sleep(0.4)
                    except Exception:
                        pass
                proc.terminate()
                try:
                    proc.wait(timeout=1.5)
                except Exception:
                    proc.kill()
            except Exception as e:
                self.log(f"Warning: failed to terminate process: {e}")

    def export_report(self, run_dir: str) -> Tuple[bool, str]:
        try:
            run_path = Path(run_dir)
            findings_path = run_path / "findings.json"
            if not findings_path.exists():
                return False, f"findings.json not found in {run_dir}."

            findings = json.loads(findings_path.read_text(encoding="utf-8"))
            ai = None
            try:
                ai = analyze_findings(findings)
            except Exception as e:
                self.log(f"AI analysis skipped (error): {e}")

            out = export_reports(run_dir=run_dir, findings=findings, ai_result=ai)
            return True, f"Saved:\n- {out['md']}\n- {out['html']}"
        except Exception as e:
            return False, str(e)

    def _worker_main(self, t: Any, mode: str, job_ids: List[str], terminal_choice: str, run_dir: str) -> None:
        tools = Tooling.detect()
        self.log(f"Run dir: {run_dir}")
        self.log(f"Target → host={t.host} ip={t.ip or 'N/A'} url={t.url}")
        self.log(f"Mode → {mode}")
        self.log(f"Dependencies detected → {', '.join(sorted(tools.present)) or '(none)'}")

        if terminal_choice != "None (GUI only)":
            try:
                open_terminal_tail(terminal_choice=terminal_choice, run_dir=run_dir)
            except Exception as e:
                self.log(f"Terminal viewer not started: {e}")

        jobs_doc = self._jobs_doc
        jobs_map = {j["id"]: j for j in jobs_doc.get("jobs", [])}
        pipelines = jobs_doc.get("pipelines", {})

        all_step_results: Dict[str, List[StepResult]] = {}

        try:
            for jid in job_ids:
                if self._stop_evt.is_set():
                    break

                job = jobs_map.get(jid)
                if not job:
                    self.log(f"Unknown job id: {jid} (skipped)")
                    continue

                self._set_state(active_job=jid, human=f"Running → {jid} {job.get('title','')}")
                self.log(f"=== JOB {jid}: {job.get('title','')} ===")

                steps = expand_pipelines(job.get("pipeline", []), pipelines)
                step_results: List[StepResult] = []

                for step in steps:
                    if self._stop_evt.is_set():
                        break
                    res = self._run_step(step=step, t=t, mode=mode, tools=tools, run_dir=run_dir)
                    step_results.append(res)

                    delay = int(step.get("post_delay_sec", 1 if mode == "safe" else 2))
                    for _ in range(delay * 5):
                        if self._stop_evt.is_set():
                            break
                        time.sleep(0.2)

                all_step_results[jid] = step_results

            self.log("Building findings.json …")
            findings = build_findings_json(
                run_dir=run_dir,
                target=t,
                mode=mode,
                step_results=all_step_results,
                tools_present=sorted(tools.present),
            )
            Path(run_dir, "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")

            self._set_state(state=RunState.DONE, human="Done", active_job=None)
            self.log("Done. You can Export Report now.")
        except Exception as e:
            self._set_state(state=RunState.ERROR, human=f"Error: {e}", active_job=None)
            self.log(f"ERROR: {e}")
        finally:
            with self._lock:
                self._current_pgid = None
                self._current_proc = None

    def _select_argv_template(self, step: Dict[str, Any]) -> List[str]:
        """
        Backward compatible:
        - prefer argv_posix / argv_windows when present
        - else fall back to argv
        """
        if os.name == "nt" and isinstance(step.get("argv_windows"), list):
            return step["argv_windows"]
        if os.name == "posix" and isinstance(step.get("argv_posix"), list):
            return step["argv_posix"]
        if isinstance(step.get("argv"), list):
            return step["argv"]
        return []

    def _run_step(self, step: Dict[str, Any], t: Any, mode: str, tools: Tooling, run_dir: str) -> StepResult:
        step_name = step.get("name", "Unnamed step")

        allowed_modes = step.get("modes", ["safe", "extended"])
        if mode not in allowed_modes:
            self.log(f"[skip] {step_name} (mode={mode})")
            now = time.time()
            return StepResult(step_name, [], int(step.get("timeout_sec", 20)), now, now, None, True, f"mode '{mode}' not allowed", None)

        requires = step.get("requires", [])
        for tool in requires:
            if tool not in tools.present:
                self.log(f"[skip] {step_name} (missing dependency: {tool})")
                now = time.time()
                return StepResult(step_name, [], int(step.get("timeout_sec", 20)), now, now, None, True, f"missing dependency: {tool}", None)

        if step.get("requires_root", False):
            if (not hasattr(os, "geteuid")) or (os.geteuid() != 0):  # type: ignore[attr-defined]
                self.log(f"[skip] {step_name} (requires root)")
                now = time.time()
                return StepResult(step_name, [], int(step.get("timeout_sec", 20)), now, now, None, True, "requires root", None)

        timeout_sec = int(step.get("timeout_sec", 20))
        output_rel = step.get("output_file")
        output_file = str(Path(run_dir, output_rel)) if output_rel else None
        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)

        # Skip duplicates within same run if configured
        if output_file and step.get("skip_if_exists", False) and Path(output_file).exists():
            self.log(f"[skip] {step_name} (skip_if_exists: {output_rel})")
            now = time.time()
            return StepResult(step_name, [], timeout_sec, now, now, None, True, "skip_if_exists", output_file)

        ctx = {
            "target": t.raw,
            "target_host": t.host,
            "target_ip": t.ip or "",
            "target_url": t.url,
            "target_port": str(t.port or ""),
            "run_dir": run_dir,
            "output_file": output_file or "",
        }

        argv_tmpl = self._select_argv_template(step)
        argv = safe_format_argv(argv_tmpl, ctx)

        # If template requires target_ip but we don't have it, skip safely
        if any("{target_ip}" in part for part in argv_tmpl) and not (t.ip or ""):
            self.log(f"[skip] {step_name} (target_ip not resolved; use IP or ensure DNS works)")
            now = time.time()
            return StepResult(step_name, argv, timeout_sec, now, now, None, True, "target_ip not resolved", output_file)

        started = time.time()
        self.log(f"→ {step_name}")
        self.log(f"   $ {' '.join(argv)}")

        rc = self._exec_stream(argv=argv, timeout_sec=timeout_sec, output_file=output_file)
        ended = time.time()

        if rc == 0:
            self.log(f"✓ {step_name} (ok)")
        elif rc is None:
            self.log(f"⚠ {step_name} (timeout / stopped)")
        else:
            self.log(f"⚠ {step_name} (rc={rc})")

        return StepResult(step_name, argv, timeout_sec, started, ended, rc, False, None, output_file)

    def _terminate_proc(self, proc: Any) -> None:
        try:
            if os.name == "posix":
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    time.sleep(0.5)
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
            else:
                if os.name == "nt":
                    try:
                        proc.send_signal(signal.CTRL_BREAK_EVENT)
                        time.sleep(0.3)
                    except Exception:
                        pass
                try:
                    proc.terminate()
                    proc.wait(timeout=1.5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
        except Exception:
            pass

    def _exec_stream(self, argv: List[str], timeout_sec: int, output_file: Optional[str]) -> Optional[int]:
        import subprocess

        started = time.monotonic()
        out_fp = open(output_file, "w", encoding="utf-8", errors="replace") if output_file else None

        popen_kwargs: Dict[str, Any] = dict(
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        if os.name == "posix":
            popen_kwargs["preexec_fn"] = os.setsid
        else:
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            proc = subprocess.Popen(argv, **popen_kwargs)
        except FileNotFoundError:
            self.log(f"Command not found: {argv[0]}")
            if out_fp:
                out_fp.write(f"Command not found: {argv[0]}\n")
                out_fp.close()
            return 127
        except Exception as e:
            self.log(f"Failed to start process: {e}")
            if out_fp:
                out_fp.write(f"Failed to start process: {e}\n")
                out_fp.close()
            return 1

        with self._lock:
            self._current_proc = proc

        if os.name == "posix":
            try:
                pgid = os.getpgid(proc.pid)
                with self._lock:
                    self._current_pgid = pgid
            except Exception:
                pass

        line_q: "queue.Queue[Optional[str]]" = queue.Queue()

        def _reader() -> None:
            try:
                if proc.stdout is not None:
                    for line in proc.stdout:
                        line_q.put(line.rstrip("\n"))
            except Exception:
                pass
            finally:
                line_q.put(None)

        t_reader = threading.Thread(target=_reader, daemon=True)
        t_reader.start()

        reader_done = False

        try:
            while True:
                if self._stop_evt.is_set():
                    self._terminate_proc(proc)
                    return None

                if (time.monotonic() - started) > timeout_sec:
                    self.log(f" Timeout reached, ({timeout_sec}s)  terminating step…")
                    self._terminate_proc(proc)
                    return None

                drained_any = False
                while True:
                    try:
                        item = line_q.get_nowait()
                    except queue.Empty:
                        break
                    drained_any = True
                    if item is None:
                        reader_done = True
                        break
                    if item:
                        self.log(item)
                        if out_fp:
                            out_fp.write(item + "\n")

                if proc.poll() is not None:
                    if reader_done or proc.stdout is None:
                        return proc.returncode

                if not drained_any:
                    time.sleep(0.05)
        finally:
            if out_fp:
                out_fp.close()
            with self._lock:
                self._current_proc = None
                self._current_pgid = None
