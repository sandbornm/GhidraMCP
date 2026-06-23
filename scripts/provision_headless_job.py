#!/usr/bin/env python3
"""
Provision/start one headless Ghidra job without touching other running jobs.

Features:
- Creates or updates job.json for a single job dir
- Chooses a non-conflicting port when needed
- Starts only the target job (does not stop/restart others)
- Waits until /health is ready
- Optionally adds/updates a Cursor MCP entry for this job
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import time
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse

from ghidra_farm import JobConfigError, load_job_spec, spawn_job


DEFAULT_GDB_SERVER = os.getenv("GHIDRA_GDB_SERVER", os.getenv("GDB_SERVER", "http://127.0.0.1:5051/"))
IGNORE_FILES = {
    "README",
    "README.md",
    "job.json",
    "server.json",
    "ghidra_headless.pid",
    "ghidra_headless.log",
}
IGNORE_EXTS = {".md", ".txt", ".json", ".log", ".yaml", ".yml"}


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "job"


def _is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _pid_from_file(pid_path: Path) -> int | None:
    if not pid_path.exists():
        return None
    try:
        return int(pid_path.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def _http_ok(url: str, timeout_s: float = 1.0) -> bool:
    try:
        with urlrequest.urlopen(url, timeout=timeout_s) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def _find_binary(job_dir: Path) -> str:
    candidates: list[Path] = []
    for p in sorted(job_dir.iterdir()):
        if not p.is_file():
            continue
        if p.name in IGNORE_FILES:
            continue
        if p.suffix.lower() in IGNORE_EXTS:
            continue
        candidates.append(p)

    if not candidates:
        raise FileNotFoundError(
            f"No candidate binary found in {job_dir}. Pass --binary with a filename under this job directory."
        )
    if len(candidates) == 1:
        return candidates[0].name

    ranked = sorted(candidates, key=lambda p: p.stat().st_size, reverse=True)
    return ranked[0].name


def _can_bind(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def _extract_port(url: str) -> int | None:
    try:
        parsed = urlparse(url)
        return parsed.port
    except Exception:
        return None


def _collect_used_ports(jobs_root: Path, mcp_config_path: Path) -> set[int]:
    used: set[int] = set()

    # Existing per-job configs
    for p in jobs_root.iterdir():
        if not p.is_dir():
            continue
        for cfg_name in ("job.json", "server.json"):
            cfg = p / cfg_name
            if not cfg.exists():
                continue
            try:
                raw = json.loads(cfg.read_text(encoding="utf-8"))
                port = raw.get("port")
                if isinstance(port, int):
                    used.add(port)
                url = raw.get("url")
                if isinstance(url, str):
                    parsed_port = _extract_port(url)
                    if parsed_port:
                        used.add(parsed_port)
            except Exception:
                continue

    # Existing MCP entries
    if mcp_config_path.exists():
        try:
            mcp = json.loads(mcp_config_path.read_text(encoding="utf-8"))
            for srv in (mcp.get("mcpServers") or {}).values():
                args = srv.get("args") if isinstance(srv, dict) else None
                if not isinstance(args, list):
                    continue
                for idx, val in enumerate(args):
                    if val == "--ghidra-server" and idx + 1 < len(args):
                        parsed_port = _extract_port(str(args[idx + 1]))
                        if parsed_port:
                            used.add(parsed_port)
        except Exception:
            pass

    return used


def _pick_port(host: str, jobs_root: Path, mcp_config_path: Path) -> int:
    used = _collect_used_ports(jobs_root, mcp_config_path)
    for port in range(18080, 18250):
        if port in used:
            continue
        if _can_bind(host, port):
            return port
    raise RuntimeError("Could not find a free port in range 18080-18249")


def _ensure_job_json(
    job_dir: Path,
    jobs_root: Path,
    mcp_config_path: Path,
    binary: str | None,
    bind_host: str,
    xmx_gb: int,
) -> dict[str, Any]:
    cfg_path = job_dir / "job.json"
    existing: dict[str, Any] = {}
    if cfg_path.exists():
        raw = json.loads(cfg_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"{cfg_path} must contain a JSON object")
        existing = raw

    chosen_binary = binary or str(existing.get("binary") or "").strip() or _find_binary(job_dir)
    binary_path = (job_dir / chosen_binary).resolve()
    if not binary_path.exists():
        raise FileNotFoundError(f"Binary does not exist: {binary_path}")
    if job_dir.resolve() not in binary_path.resolve().parents:
        raise ValueError("Binary must be inside the job directory")

    port_val = existing.get("port")
    if isinstance(port_val, int) and 1 <= port_val <= 65535:
        port = port_val
    else:
        port = _pick_port(bind_host, jobs_root, mcp_config_path)

    job_id = str(existing.get("job_id") or _slugify(job_dir.name))
    java_opts = existing.get("java_opts")
    if not isinstance(java_opts, list) or not java_opts:
        java_opts = [f"-Xmx{xmx_gb}g"]

    updated = {
        "job_id": job_id,
        "binary": chosen_binary,
        "analyze": bool(existing.get("analyze", True)),
        "java_opts": java_opts,
        "bind_host": str(existing.get("bind_host") or bind_host),
        "port": port,
        "project_dir": str(existing.get("project_dir") or ".ghidra_project"),
        "project_name": str(existing.get("project_name") or "GhidraMCP"),
    }
    cfg_path.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
    return updated


def _wait_for_health(url: str, timeout_s: int) -> None:
    deadline = time.time() + timeout_s
    health = f"{url.rstrip('/')}/health"
    while time.time() < deadline:
        if _http_ok(health, timeout_s=1.0):
            return
        time.sleep(1)
    raise TimeoutError(f"Timed out waiting for {health}")


def _update_mcp_config(
    mcp_config_path: Path,
    mcp_name: str,
    ghidra_url: str,
    gdb_server: str,
    repo_root: Path,
) -> None:
    mcp_data: dict[str, Any] = {"mcpServers": {}}
    if mcp_config_path.exists():
        raw = json.loads(mcp_config_path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            mcp_data = raw
    servers = mcp_data.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise ValueError("mcpServers must be an object")

    servers[mcp_name] = {
        "command": "/opt/homebrew/bin/uv",
        "args": [
            "run",
            "--script",
            str(repo_root / "bridge_mcp_static.py"),
            "--ghidra-server",
            ghidra_url,
            "--gdb-server",
            gdb_server,
        ],
    }
    mcp_config_path.write_text(json.dumps(mcp_data, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision and start one headless Ghidra job safely.")
    parser.add_argument("--job-dir", required=True, type=Path, help="Path to one job directory (e.g. ~/ghidra-jobs/NewJob)")
    parser.add_argument("--binary", default=None, help="Binary filename relative to --job-dir (auto-detect if omitted)")
    parser.add_argument(
        "--ghidra-install-dir",
        default=os.path.expanduser("~/tools/ghidra_11.4.2_PUBLIC"),
        type=Path,
        help="Ghidra install dir containing support/analyzeHeadless",
    )
    parser.add_argument("--script-path", default=Path(__file__).resolve().parents[1] / "ghidra_scripts", type=Path)
    parser.add_argument("--bind-host", default="127.0.0.1")
    parser.add_argument("--xmx-gb", type=int, default=4)
    parser.add_argument("--wait-timeout", type=int, default=600)
    parser.add_argument("--gdb-server", default=DEFAULT_GDB_SERVER)
    parser.add_argument("--mcp-name", default=None, help="Cursor MCP server name (default: ghidra-<job-slug>)")
    parser.add_argument(
        "--mcp-config",
        default=os.path.expanduser("~/.cursor/mcp.json"),
        type=Path,
        help="Cursor MCP config path",
    )
    parser.add_argument("--no-mcp-update", action="store_true", help="Do not update Cursor MCP config")
    parser.add_argument("--force-restart", action="store_true", help="Terminate existing PID for this job before spawn")
    args = parser.parse_args()

    job_dir = args.job_dir.expanduser().resolve()
    if not job_dir.exists() or not job_dir.is_dir():
        raise FileNotFoundError(f"Job directory does not exist: {job_dir}")
    jobs_root = job_dir.parent
    repo_root = Path(__file__).resolve().parents[1]

    job_cfg = _ensure_job_json(
        job_dir=job_dir,
        jobs_root=jobs_root,
        mcp_config_path=args.mcp_config.expanduser().resolve(),
        binary=args.binary,
        bind_host=args.bind_host,
        xmx_gb=args.xmx_gb,
    )
    port = int(job_cfg["port"])
    url = f"http://{job_cfg['bind_host']}:{port}/"
    health_url = f"{url}health"

    pid_path = job_dir / "ghidra_headless.pid"
    pid = _pid_from_file(pid_path)
    if pid and _is_running(pid) and _http_ok(health_url):
        started = False
    else:
        if pid and _is_running(pid):
            if not args.force_restart:
                raise RuntimeError(
                    f"Job PID {pid} exists but health is not ready. Use --force-restart or inspect {job_dir / 'ghidra_headless.log'}."
                )
            os.killpg(pid, signal.SIGTERM)
            time.sleep(1)

        spec = load_job_spec(
            job_dir=job_dir,
            ghidra_install_dir=args.ghidra_install_dir.expanduser().resolve(),
            default_bind_host=args.bind_host,
        )
        spawn_job(spec, script_path_dir=args.script_path.expanduser().resolve(), dry_run=False)
        started = True
        _wait_for_health(url, timeout_s=args.wait_timeout)

    mcp_name = args.mcp_name or f"ghidra-{_slugify(job_dir.name)}"
    if not args.no_mcp_update:
        _update_mcp_config(
            mcp_config_path=args.mcp_config.expanduser().resolve(),
            mcp_name=mcp_name,
            ghidra_url=url,
            gdb_server=args.gdb_server,
            repo_root=repo_root,
        )

    print(
        json.dumps(
            {
                "status": "ready",
                "job_dir": str(job_dir),
                "binary": job_cfg["binary"],
                "ghidra_server": url,
                "health_url": health_url,
                "started_new_process": started,
                "mcp_name": mcp_name,
                "mcp_updated": not args.no_mcp_update,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (JobConfigError, FileNotFoundError, TimeoutError, ValueError, RuntimeError) as e:
        print(f"error: {e}", flush=True)
        raise SystemExit(2)
