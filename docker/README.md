# GDB Dynamic Analysis Container

Docker container providing a full x86-64 Linux environment for dynamic analysis, running on ARM Mac via QEMU emulation.

## Features

### Debugging & Execution
- **GDB** with GEF (GDB Enhanced Features)
- **strace** / **ltrace** - system call and library call tracing
- **Single-stepping** - stepi, nexti, step, next with state capture
- **Register inspection** - full CPU register dump at breakpoints
- **Memory inspection** - read memory as hex, strings, or disassembly
- **Watchpoints** - hardware write/read/access watchpoints
- **Stack inspection** - backtrace, frame info, stack memory dump
- **Heap analysis** - GEF-powered heap chunks, bins, arenas

### Binary Analysis
- **checksec** - NX, PIE, RELRO, stack canary detection
- **objdump** - disassembly (Intel syntax)
- **readelf** - ELF headers, sections, symbols, dynamic info
- **binwalk** - embedded file and signature detection
- **entropy** - packing/encryption detection
- **GOT/PLT** - dynamic linking table inspection
- **ROP gadgets** - gadget finding via ropper/ROPGadget

### Instrumentation
- **Frida** - dynamic instrumentation framework
  - Arbitrary JS instrumentation scripts
  - Function call tracing
  - Function hooking with onEnter/onLeave callbacks
- **Packet capture analysis** - `tcpdump` + `tshark` for network traffic inspection
  - Capture live traffic to `.pcap` files
  - Protocol hierarchy, conversations, and endpoint summaries
  - CSV packet previews with protocol/length metadata

### Libraries Available
- `pyelftools`, `lief` - ELF/binary parsing
- `pefile` - PE (Windows) binary parsing
- `pycryptodome` - cryptographic primitives
- `capstone` / `keystone-engine` / `unicorn` - disassembly, assembly, emulation
- `ropper` / `ROPGadget` - ROP gadget finding
- `angr` - symbolic execution (headless via `/angr/explore`, `/angr/cfg`, `/angr/entry`)
- `z3-solver` - SMT constraint solver
- `frida-tools` - Frida instrumentation
- `pwntools` - exploit development

### QEMU & Windows PE
- **QEMU user-mode**: Emulates Linux binaries across architectures (ARM, MIPS, etc.) on x86-64.
- **Windows PE**: QEMU user-mode does NOT run Windows executables. For PE analysis use `gdb_pe_info`.
  Optional: Add `wine64` to the Dockerfile to run Windows PE on Linux.

## Quick Start

```bash
# Build and start the container
cd docker
docker-compose up -d --build

# Check if it's running
curl http://127.0.0.1:5051/health

# Stop the container
docker-compose down
```

## Usage with Claude

### Execution & Debugging
| Tool | Description |
|------|-------------|
| `gdb_run_binary(binary, args, stdin)` | Run binary and capture output |
| `gdb_execute(binary, commands)` | Execute raw GDB commands |
| `gdb_breakpoint_run(binary, breakpoints)` | Run with breakpoints, capture state |
| `gdb_read_registers(binary, breakpoint)` | Dump all CPU registers |
| `gdb_read_memory(binary, addr, len, fmt)` | Read memory (hex/string/instructions) |
| `gdb_step_execution(binary, bp, cmd, count)` | Single-step (stepi/nexti/step/next) |
| `gdb_set_watchpoint(binary, expr, type)` | Set hardware watchpoints |
| `gdb_inspect_stack(binary, breakpoint)` | Full stack frame inspection |
| `gdb_analyze_heap(binary, breakpoint)` | GEF heap analysis |
| `gdb_vmmap(binary, breakpoint)` | Virtual memory map |
| `gdb_search_pattern(binary, pattern)` | Search pattern in process memory |

### Tracing & Instrumentation
| Tool | Description |
|------|-------------|
| `gdb_strace(binary)` | Trace system calls |
| `gdb_ltrace(binary)` | Trace library calls |
| `gdb_capture_pcap(interface, duration, filter)` | Capture network traffic to PCAP |
| `gdb_analyze_pcap(pcap, display_filter)` | Analyze PCAP with tshark summaries |
| `gdb_list_pcaps()` | List saved packet captures |
| `gdb_frida_instrument(binary, script)` | Run Frida JS instrumentation |
| `gdb_frida_trace(binary, functions)` | Trace function calls via Frida |
| `gdb_frida_hook(binary, target, on_enter)` | Hook functions with callbacks |

### Binary Analysis
| Tool | Description |
|------|-------------|
| `gdb_checksec(binary)` | Check security features |
| `gdb_pe_info(binary)` | PE (Windows) structure, sections, imports, exports |
| `gdb_got_plt(binary)` | GOT/PLT table entries |
| `gdb_rop_gadgets(binary, filter)` | Find ROP gadgets |
| `gdb_entropy(binary)` | Packing/encryption detection |
| `gdb_binwalk(binary)` | Embedded file detection |

### Angr Symbolic Execution
| Tool | Description |
|------|-------------|
| `angr_explore(binary, find_addr)` | Find stdin that reaches target address |
| `angr_cfg(binary)` | Control flow graph (nodes, edges) |
| `angr_entry(binary)` | Entry point and main address |
| `gdb_angr_selftest(timeout)` | Validate angr runtime + symbolic exploration |

### Autonomous
| Tool | Description |
|------|-------------|
| `auto_triage(binary)` | Run full triage pipeline (file_info, checksec, entropy, imports, strings) |

## API Endpoints

### Core
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/list_bins` | GET | List binaries |
| `/upload` | POST | Upload binary (multipart) |
| `/run` | POST | Run binary |
| `/logs` | GET | Server logs |
| `/telemetry` | GET | Tool-level telemetry |
| `/command_telemetry` | GET | Command history + output snapshots |
| `/angr/selftest` | POST | angr runtime health/self-test |

### GDB Debugging
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/gdb` | POST | Execute GDB commands |
| `/gdb/breakpoint_run` | POST | Run with breakpoints |
| `/gdb/registers` | POST | Read registers at breakpoint |
| `/gdb/memory` | POST | Read memory (hex/string/asm) |
| `/gdb/step` | POST | Step execution |
| `/gdb/watchpoint` | POST | Set watchpoints |
| `/gdb/stack` | POST | Stack inspection |
| `/gdb/heap` | POST | Heap analysis (GEF) |
| `/gdb/vmmap` | POST | Virtual memory map |
| `/gdb/search_pattern` | POST | Search memory for pattern |

### Instrumentation
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/strace` | POST | System call trace |
| `/ltrace` | POST | Library call trace |
| `/pcap/list` | GET | List saved PCAP files |
| `/pcap/capture` | POST | Capture live traffic with tcpdump |
| `/pcap/analyze` | POST | Analyze PCAP via tshark summaries |
| `/frida/attach` | POST | Run Frida script |
| `/frida/trace` | POST | Trace functions with Frida |
| `/frida/hook` | POST | Hook function with Frida |

### Analysis
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/checksec` | POST | Security features |
| `/disassemble` | POST | Disassemble binary |
| `/strings` | POST | Extract strings |
| `/file_info` | POST | File information |
| `/readelf` | POST | ELF structure |
| `/sections` | POST | Section info |
| `/symbols` | POST | Symbol table |
| `/entropy` | POST | Entropy analysis |
| `/binwalk` | POST | Embedded files |
| `/got_plt` | POST | GOT/PLT entries |
| `/rop_gadgets` | POST | ROP gadgets |
| `/patch_elf` | POST | Patch ELF binary |

## Architecture

```
+------------------------------------------------------------------+
|                         Host Machine                              |
|                                                                   |
|  +-------------+     +-------------+     +---------------------+ |
|  |   Ghidra    |     |   Claude    |     |  Docker (QEMU)      | |
|  |   :8080     |     |   Desktop   |     |  +---------------+  | |
|  +------+------+     +------+------+     |  | x86-64 Linux  |  | |
|         |                   |            |  |               |  | |
|         |    MCP Protocol   |            |  | GDB + GEF     |  | |
|         |         |         |            |  | Frida         |  | |
|         |         v         |            |  | pwntools      |  | |
|         |  +--------------+ |            |  | angr / z3     |  | |
|         +->|  MCP Bridge  |<+            |  |   :5051       |  | |
|            |  (Python)    |<----HTTP---->|  +---------------+  | |
|            +--------------+              +---------------------+ |
+------------------------------------------------------------------+
```
