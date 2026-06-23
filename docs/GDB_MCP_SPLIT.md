# GDB MCP Split Guide

This project now supports a clean static/dynamic MCP split:

- `bridge_mcp_static.py` -> per-binary static Ghidra endpoints (headless farm URL)
- `bridge_mcp_gdb.py` -> dynamic GDB/Docker endpoints (single shared backend)

## Why this split

- Lower tool confusion for static reversing sessions.
- Better fault isolation (GDB container issues do not affect static decompilation).
- Easier future extraction of dynamic tooling into a separate repository.

## Port defaults

- Static Ghidra servers: per-job ports (e.g. `18080`, `18081`)
- GDB API host/container port: `5051` by default in `docker/docker-compose.yml`

Override host GDB port at runtime:

```bash
cd docker
GDB_HTTP_PORT=5101 docker compose up -d --build
```

## Environment variables

Both bridges support:

- `GHIDRA_SERVER` (static bridge default)
- `GHIDRA_GDB_SERVER` (preferred dynamic URL override)
- `GDB_SERVER` (fallback dynamic URL override)

## Interop flow

Use static MCP for patching, then pass artifacts to dynamic MCP:

1. static tool: `export_binary(...)`
2. static helper (or dynamic tool): `export_and_upload_to_gdb(...)` or `gdb_upload_binary(...)`
3. dynamic tooling: `gdb_run_binary`, `gdb_breakpoint_run`, `angr_explore`, etc.

## Extracting `bridge_mcp_gdb.py` to a separate repository

`bridge_mcp_gdb.py` is intentionally standalone:

- no imports from repo-local modules
- only depends on:
  - `requests`
  - `mcp`

Minimal extraction steps:

1. Copy `bridge_mcp_gdb.py` into the new repo.
2. Keep the script header (`requires-python` + dependencies) so `uv run --script` works.
3. Update Cursor MCP config to point to the new script path.
4. Keep `--gdb-server` target set to your Docker host URL.
