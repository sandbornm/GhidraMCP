#!/usr/bin/env python3
"""
Spawn one isolated Ghidra (headless) process per job directory.

Each job directory must contain a `job.json` that points at a single binary.
The launcher starts `analyzeHeadless` with a postScript that runs a long-lived
HTTP API server (one port per job).

This is designed for "one agent per binary" concurrency: process-level isolation.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class JobConfigError(RuntimeError):
    pass


def _now_unix() -> int:
    return int(time.time())


def _pick_free_tcp_port(bind_host: str) -> int:
    # Best-effort port allocation. There's an inherent TOCTOU race, but in practice
    # it's good enough when used immediately for spawning a child process.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((bind_host, 0))
        s.listen(1)
        return int(s.getsockname()[1])


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except Exception:
        return False


def _require_str(obj: dict[str, Any], key: str) -> str:
    val = obj.get(key)
    if not isinstance(val, str) or not val.strip():
        raise JobConfigError(f"`{key}` must be a non-empty string")
    return val


def _optional_str(obj: dict[str, Any], key: str) -> str | None:
    val = obj.get(key)
    if val is None:
        return None
    if not isinstance(val, str) or not val.strip():
        raise JobConfigError(f"`{key}` must be a non-empty string when provided")
    return val


def _optional_bool(obj: dict[str, Any], key: str, default: bool) -> bool:
    val = obj.get(key, default)
    if isinstance(val, bool):
        return val
    raise JobConfigError(f"`{key}` must be a boolean when provided")


def _optional_int(obj: dict[str, Any], key: str) -> int | None:
    val = obj.get(key)
    if val is None:
        return None
    if isinstance(val, int):
        return val
    raise JobConfigError(f"`{key}` must be an integer when provided")


def _optional_str_list(obj: dict[str, Any], key: str) -> list[str]:
    """
    Accept either:
      - ["-Xmx4g", "-XX:..."]
      - "-Xmx4g -XX:..." (split on whitespace)
    """
    val = obj.get(key)
    if val is None:
        return []
    if isinstance(val, str):
        parts = val.split()
        if not parts:
            raise JobConfigError(f"`{key}` must not be empty when provided")
        return parts
    if isinstance(val, list) and all(isinstance(x, str) and x.strip() for x in val):
        return [x.strip() for x in val]
    raise JobConfigError(f"`{key}` must be a string or a list of strings when provided")


@dataclass(frozen=True)
class JobSpec:
    job_id: str
    job_dir: Path
    binary_path: Path
    project_dir: Path
    project_name: str
    analyze: bool
    bind_host: str
    port: int
    ghidra_install_dir: Path
    java_opts: list[str]

    @property
    def ghidra_url(self) -> str:
        return f"http://{self.bind_host}:{self.port}/"

    @property
    def analyze_headless_path(self) -> Path:
        return self.ghidra_install_dir / "support" / "analyzeHeadless"

    @property
    def log_path(self) -> Path:
        return self.job_dir / "ghidra_headless.log"

    @property
    def pid_path(self) -> Path:
        return self.job_dir / "ghidra_headless.pid"

    @property
    def server_info_path(self) -> Path:
        return self.job_dir / "server.json"


def load_job_spec(*, job_dir: Path, ghidra_install_dir: Path, default_bind_host: str) -> JobSpec:
    job_json_path = job_dir / "job.json"
    if not job_json_path.exists():
        raise JobConfigError(f"Missing job.json in {job_dir}")

    try:
        raw = json.loads(job_json_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise JobConfigError(f"Failed to parse {job_json_path}: {e}") from e

    if not isinstance(raw, dict):
        raise JobConfigError(f"{job_json_path} must be a JSON object")

    binary_rel = _require_str(raw, "binary")
    binary_path = (job_dir / binary_rel).resolve()
    if not binary_path.exists():
        raise JobConfigError(f"Binary not found: {binary_path}")
    if not binary_path.is_file():
        raise JobConfigError(f"Binary path is not a file: {binary_path}")
    if not _is_relative_to(binary_path, job_dir):
        raise JobConfigError("For safety, `binary` must resolve under the job directory")

    analyze = _optional_bool(raw, "analyze", True)
    bind_host = _optional_str(raw, "bind_host") or default_bind_host

    project_dir_rel = _optional_str(raw, "project_dir") or ".ghidra_project"
    project_dir = (job_dir / project_dir_rel).resolve()
    if not _is_relative_to(project_dir, job_dir):
        raise JobConfigError("For safety, `project_dir` must resolve under the job directory")

    project_name = _optional_str(raw, "project_name") or "GhidraMCP"

    port = _optional_int(raw, "port")
    if port is None:
        port = _pick_free_tcp_port(bind_host)
    if not (1 <= port <= 65535):
        raise JobConfigError("`port` must be in range 1..65535")

    job_id = _optional_str(raw, "job_id") or job_dir.name
    java_opts = _optional_str_list(raw, "java_opts")

    return JobSpec(
        job_id=job_id,
        job_dir=job_dir,
        binary_path=binary_path,
        project_dir=project_dir,
        project_name=project_name,
        analyze=analyze,
        bind_host=bind_host,
        port=port,
        ghidra_install_dir=ghidra_install_dir.resolve(),
        java_opts=java_opts,
    )


def build_analyze_headless_cmd(*, job: JobSpec, script_path_dir: Path) -> list[str]:
    analyze_headless = job.analyze_headless_path
    if not analyze_headless.exists():
        raise FileNotFoundError(f"analyzeHeadless not found at {analyze_headless}")

    # Ensure project dir exists (analyzeHeadless will create project contents).
    job.project_dir.mkdir(parents=True, exist_ok=True)

    cmd: list[str] = [
        str(analyze_headless),
        str(job.project_dir),
        job.project_name,
        "-import",
        str(job.binary_path),
        "-scriptPath",
        str(script_path_dir),
        "-postScript",
        "GhidraMCPHeadlessServer.java",
        "--bind",
        job.bind_host,
        "--port",
        str(job.port),
    ]

    if not job.analyze:
        cmd.append("-noanalysis")

    return cmd


def spawn_job(job: JobSpec, *, script_path_dir: Path, dry_run: bool) -> dict[str, Any]:
    cmd = build_analyze_headless_cmd(job=job, script_path_dir=script_path_dir)
    cmd_str = " ".join(shlex.quote(c) for c in cmd)

    # Write server info early so orchestration tooling can see intent even if spawn fails.
    server_info: dict[str, Any] = {
        "job_id": job.job_id,
        "job_dir": str(job.job_dir),
        "binary_path": str(job.binary_path),
        "project_dir": str(job.project_dir),
        "project_name": job.project_name,
        "bind_host": job.bind_host,
        "port": job.port,
        "url": job.ghidra_url,
        "analyze": job.analyze,
        "java_opts": job.java_opts,
        "command": cmd,
        "command_str": cmd_str,
        "started_at_unix": _now_unix(),
    }

    # analyzeHeadless is a shell wrapper; the most portable way to influence memory/cpu
    # behavior from an external launcher is via environment variables.
    env = os.environ.copy()
    if job.java_opts:
        existing = env.get("JAVA_OPTS", "").strip()
        merged = (existing + " " + " ".join(job.java_opts)).strip()
        env["JAVA_OPTS"] = merged
        server_info["java_opts_env"] = {"JAVA_OPTS": merged}

    if dry_run:
        server_info["dry_run"] = True
        job.server_info_path.write_text(json.dumps(server_info, indent=2) + "\n", encoding="utf-8")
        return server_info

    with open(job.log_path, "ab", buffering=0) as logf:
        proc = subprocess.Popen(
            cmd,
            cwd=str(job.job_dir),
            stdout=logf,
            stderr=logf,
            env=env,
            start_new_session=True,  # separate process group; easier to terminate job
        )

    job.pid_path.write_text(f"{proc.pid}\n", encoding="utf-8")
    server_info["pid"] = proc.pid
    job.server_info_path.write_text(json.dumps(server_info, indent=2) + "\n", encoding="utf-8")
    return server_info


def _iter_job_dirs(jobs_root: Path) -> list[Path]:
    if not jobs_root.exists():
        raise FileNotFoundError(f"Jobs root does not exist: {jobs_root}")
    if not jobs_root.is_dir():
        raise NotADirectoryError(f"Jobs root is not a directory: {jobs_root}")

    job_dirs: list[Path] = []
    for p in sorted(jobs_root.iterdir()):
        if p.is_dir() and (p / "job.json").exists():
            job_dirs.append(p)
    return job_dirs


def terminate_job(job_dir: Path, *, sig: int) -> bool:
    pid_path = job_dir / "ghidra_headless.pid"
    if not pid_path.exists():
        return False

    pid_s = pid_path.read_text(encoding="utf-8").strip()
    if not pid_s:
        return False
    pid = int(pid_s)

    try:
        # We start new session, so pid is also process group leader.
        os.killpg(pid, sig)
        return True
    except ProcessLookupError:
        return False


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Spawn one headless Ghidra HTTP server per job directory.")
    ap.add_argument("jobs_root", type=Path, help="Root directory containing per-job subdirectories")
    ap.add_argument(
        "--ghidra-install-dir",
        type=Path,
        required=True,
        help="Path to Ghidra install directory (contains support/analyzeHeadless)",
    )
    ap.add_argument(
        "--bind-host",
        default="127.0.0.1",
        help="Host/interface to bind server to (default: 127.0.0.1)",
    )
    ap.add_argument(
        "--script-path",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "ghidra_scripts",
        help="Directory containing Ghidra scripts (default: repo/ghidra_scripts)",
    )
    ap.add_argument("--dry-run", action="store_true", help="Write server.json but do not spawn processes")
    ap.add_argument("--registry", type=Path, default=None, help="Optional path to write combined registry JSON")
    ap.add_argument("--stop", action="store_true", help="Stop jobs instead of starting them")
    ap.add_argument(
        "--signal",
        default="TERM",
        choices=["TERM", "KILL", "INT"],
        help="Signal to use with --stop (default: TERM)",
    )
    args = ap.parse_args(argv)

    jobs_root: Path = args.jobs_root.resolve()
    ghidra_install_dir: Path = args.ghidra_install_dir.resolve()
    script_path_dir: Path = args.script_path.resolve()

    if not script_path_dir.exists():
        raise FileNotFoundError(f"Script path does not exist: {script_path_dir}")

    job_dirs = _iter_job_dirs(jobs_root)
    if not job_dirs:
        print(f"No job directories found under {jobs_root} (expected jobs_root/*/job.json)", file=sys.stderr)
        return 2

    registry: dict[str, Any] = {"jobs_root": str(jobs_root), "generated_at_unix": _now_unix(), "jobs": []}

    if args.stop:
        sig_map = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL, "INT": signal.SIGINT}
        sig = int(sig_map[args.signal])
        stopped = 0
        for jd in job_dirs:
            if terminate_job(jd, sig=sig):
                stopped += 1
                print(f"Stopped {jd.name}")
            else:
                print(f"No running PID for {jd.name}")
        return 0 if stopped else 1

    for jd in job_dirs:
        job = load_job_spec(job_dir=jd, ghidra_install_dir=ghidra_install_dir, default_bind_host=args.bind_host)
        info = spawn_job(job, script_path_dir=script_path_dir, dry_run=bool(args.dry_run))
        registry["jobs"].append(info)
        print(f"{job.job_id}: {job.ghidra_url} ({job.binary_path.name})")

    if args.registry:
        reg_path: Path = args.registry.resolve()
        reg_path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except JobConfigError as e:
        print(f"job config error: {e}", file=sys.stderr)
        raise SystemExit(2)
