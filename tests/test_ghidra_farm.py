import json
from pathlib import Path

import pytest


@pytest.fixture()
def jobs_root(tmp_path: Path) -> Path:
    root = tmp_path / "jobs"
    root.mkdir()
    return root


def _write_job(job_dir: Path, job_json: dict, binary_name: str = "binary") -> None:
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / binary_name).write_bytes(b"\x7fELF")  # doesn't need to be valid for unit tests
    (job_dir / "job.json").write_text(json.dumps(job_json), encoding="utf-8")


def test_load_job_spec_minimal(jobs_root: Path, tmp_path: Path):
    from scripts.ghidra_farm import load_job_spec

    job_dir = jobs_root / "job1"
    _write_job(job_dir, {"binary": "binary"})

    ghidra_install = tmp_path / "ghidra"
    (ghidra_install / "support").mkdir(parents=True)
    (ghidra_install / "support" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")

    spec = load_job_spec(job_dir=job_dir, ghidra_install_dir=ghidra_install, default_bind_host="127.0.0.1")
    assert spec.job_id == "job1"
    assert spec.binary_path.name == "binary"
    assert spec.bind_host == "127.0.0.1"
    assert 1 <= spec.port <= 65535
    assert spec.java_opts == []


def test_load_job_spec_rejects_escape(jobs_root: Path, tmp_path: Path):
    from scripts.ghidra_farm import JobConfigError, load_job_spec

    job_dir = jobs_root / "job1"
    job_dir.mkdir()
    # binary path resolves outside job dir
    (jobs_root / "outside.bin").write_bytes(b"\x00")
    (job_dir / "job.json").write_text(json.dumps({"binary": "../outside.bin"}), encoding="utf-8")

    ghidra_install = tmp_path / "ghidra"
    ghidra_install.mkdir()

    with pytest.raises(JobConfigError, match="must resolve under the job directory"):
        load_job_spec(job_dir=job_dir, ghidra_install_dir=ghidra_install, default_bind_host="127.0.0.1")


def test_build_cmd_includes_postscript(jobs_root: Path, tmp_path: Path):
    from scripts.ghidra_farm import build_analyze_headless_cmd, load_job_spec

    job_dir = jobs_root / "job1"
    _write_job(job_dir, {"binary": "binary", "port": 18080, "bind_host": "127.0.0.1"})

    ghidra_install = tmp_path / "ghidra"
    (ghidra_install / "support").mkdir(parents=True)
    (ghidra_install / "support" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")

    spec = load_job_spec(job_dir=job_dir, ghidra_install_dir=ghidra_install, default_bind_host="127.0.0.1")
    cmd = build_analyze_headless_cmd(job=spec, script_path_dir=tmp_path)

    assert "-postScript" in cmd
    assert "GhidraMCPHeadlessServer.java" in cmd
    assert "--port" in cmd
    assert "18080" in cmd


def test_spawn_job_dry_run_writes_server_json(jobs_root: Path, tmp_path: Path):
    from scripts.ghidra_farm import load_job_spec, spawn_job

    job_dir = jobs_root / "job1"
    _write_job(job_dir, {"binary": "binary", "java_opts": ["-Xmx2g"]})

    ghidra_install = tmp_path / "ghidra"
    (ghidra_install / "support").mkdir(parents=True)
    (ghidra_install / "support" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")

    spec = load_job_spec(job_dir=job_dir, ghidra_install_dir=ghidra_install, default_bind_host="127.0.0.1")
    info = spawn_job(spec, script_path_dir=tmp_path, dry_run=True)

    server_json = job_dir / "server.json"
    assert server_json.exists()
    data = json.loads(server_json.read_text(encoding="utf-8"))
    assert info["dry_run"] is True
    assert data["dry_run"] is True
    assert data["job_id"] == "job1"
    assert data["url"].startswith("http://")
    assert data["java_opts"] == ["-Xmx2g"]
    assert "JAVA_OPTS" in data["java_opts_env"]
