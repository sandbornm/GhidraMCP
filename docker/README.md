# GDB Dynamic Analysis Container

This Docker container provides x86-64 Linux environment for dynamic analysis, running on ARM Mac via QEMU emulation.

## Features

- **GDB** with GEF (GDB Enhanced Features)
- **strace** - trace system calls
- **ltrace** - trace library calls
- **objdump** - disassembly
- **checksec** - check binary security features
- **pwntools** - for exploit development

## Quick Start

```bash
# Build and start the container
cd docker
docker-compose up -d --build

# Check if it's running
curl http://127.0.0.1:5000/health

# Stop the container
docker-compose down
```

## Usage with Claude

Once the container is running, Claude can use these tools:

| Tool | Description |
|------|-------------|
| `gdb_health()` | Check if container is running |
| `gdb_upload_binary(path)` | Upload a binary for analysis |
| `gdb_list_binaries()` | List uploaded binaries |
| `gdb_run_binary(name)` | Run a binary and capture output |
| `gdb_execute(name, commands)` | Run GDB commands |
| `gdb_breakpoint_run(name, breakpoints)` | Run with breakpoints, capture state |
| `gdb_strace(name)` | Trace system calls |
| `gdb_ltrace(name)` | Trace library calls |
| `gdb_checksec(name)` | Check security features |
| `gdb_disassemble(name, symbol)` | Disassemble function |

## Example Workflow

1. **Upload binary from Ghidra project:**
   ```
   "Upload /path/to/binary to the GDB container"
   ```

2. **Check security features:**
   ```
   "Run checksec on the binary"
   ```

3. **Run with strace:**
   ```
   "Trace the system calls when running with input 'hello'"
   ```

4. **Debug with GDB:**
   ```
   "Set a breakpoint at main, run, and show me the registers"
   ```

## Manual Binary Upload

You can also copy binaries directly to the `bins/` directory:

```bash
cp /path/to/your/binary docker/bins/
```

The container mounts this directory at `/analysis/bins`.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/list_bins` | GET | List binaries |
| `/upload` | POST | Upload binary (multipart) |
| `/run` | POST | Run binary |
| `/gdb` | POST | Execute GDB commands |
| `/gdb/breakpoint_run` | POST | Run with breakpoints |
| `/strace` | POST | Run strace |
| `/ltrace` | POST | Run ltrace |
| `/checksec` | POST | Check security features |
| `/disassemble` | POST | Disassemble binary |
| `/strings` | POST | Extract strings |

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         Your Mac (ARM)                           │
│                                                                  │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐│
│  │   Ghidra    │     │   Claude    │     │  Docker (QEMU)      ││
│  │   :8080     │     │   Desktop   │     │  ┌───────────────┐  ││
│  └──────┬──────┘     └──────┬──────┘     │  │ x86-64 Linux  │  ││
│         │                   │            │  │               │  ││
│         │    MCP Protocol   │            │  │  GDB + tools  │  ││
│         │         │         │            │  │    :5000      │  ││
│         │         ▼         │            │  └───────┬───────┘  ││
│         │  ┌──────────────┐ │            │          │          ││
│         └─►│  MCP Bridge  │◄┘            └──────────┼──────────┘│
│            │  (Python)    │◄─────HTTP────────────────┘           │
│            └──────────────┘                                      │
└──────────────────────────────────────────────────────────────────┘
```
