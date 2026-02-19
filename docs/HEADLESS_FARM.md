# Headless Ghidra "Farm" (One Binary Per Process)

Goal: run one isolated Ghidra process per binary so multiple agents can analyze/transform different binaries concurrently without in-process contention.

This uses:
- Ghidra's `support/analyzeHeadless`
- A long-lived Ghidra postScript: `ghidra_scripts/GhidraMCPHeadlessServer.java`
- A launcher/orchestrator: `scripts/ghidra_farm.py`

## Job Layout

Create a root directory with one subdirectory per binary:

```
jobs_root/
  job1/
    job.json
    binary
  job2/
    job.json
    somefile.exe
```

Each `job.json` points at a single binary (relative to the job directory).

### `job.json` schema

Minimal:

```json
{
  "binary": "binary"
}
```

Full:

```json
{
  "job_id": "job1",
  "binary": "binary",
  "analyze": true,
  "java_opts": ["-Xmx4g"],
  "bind_host": "127.0.0.1",
  "port": 18080,
  "project_dir": ".ghidra_project",
  "project_name": "GhidraMCP"
}
```

Notes:
- `binary` must resolve under the job directory (safety check).
- If `port` is omitted, the launcher picks a free port.
- Use `java_opts` to keep multiple concurrent headless Ghidra processes from exhausting RAM (e.g. `-Xmx2g` or `-Xmx4g` depending on your mini).

## Starting Servers

```bash
python scripts/ghidra_farm.py /path/to/jobs_root \
  --ghidra-install-dir "/path/to/ghidra_11.4.2_PUBLIC" \
  --registry /path/to/jobs_root/servers.json
```

Each job directory gets:
- `server.json` (URL + command + metadata)
- `ghidra_headless.pid`
- `ghidra_headless.log`

## Stopping Servers

```bash
python scripts/ghidra_farm.py /path/to/jobs_root \
  --ghidra-install-dir "/path/to/ghidra_11.4.2_PUBLIC" \
  --stop
```

## Connecting an Agent

Run one MCP bridge per agent, pointed at the per-job URL from `server.json`:

```bash
python bridge_mcp_ghidra.py --ghidra-server "http://127.0.0.1:18080/"
```

## Mac Mini Notes

For a complete Mac mini walkthrough (install Ghidra, quarantine/xattr, SSH port forwarding, and update procedure), see `docs/MAC_MINI_HEADLESS_SETUP.md`.

## Dockerized Ghidra (Optional)

Ghidra 11.4 includes an official "Dockerized Ghidra" capability. In principle, you can run one container per job and expose one HTTP port per container.

Trade-offs:
- Pros: process isolation + easier resource limiting (memory/cpu), no host JDK management.
- Cons: more moving parts (Docker Desktop/Colima), volume mounts for job/project dirs, and you must ensure the container has the native decompiler for the target arch.

This repo's current recommended path on Mac minis is the native `analyzeHeadless` approach. If you want the Docker route, we can add a `docker-compose` profile that runs one container per job directory and invokes `analyzeHeadless` with `GhidraMCPHeadlessServer.java`.

## Endpoint Coverage

The headless server script currently implements a core subset of the GUI plugin endpoints (enough for basic listing + decompile + rename function/data/variable + bytes + patch bytes/instruction/NOP + trigger analysis + export in original format).

If you need full tool parity with the GUI plugin, run one GUI Ghidra instance per binary (one port per instance) or extend `GhidraMCPHeadlessServer.java` with additional endpoints.

