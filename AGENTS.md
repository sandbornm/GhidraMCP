# GhidraMCP Agent Onboarding Guide

Quick-start guide for AI agents (Claude, GPT, etc.) working with this reverse engineering toolchain.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Host Machine                                 │
│                                                                     │
│  ┌──────────────┐    ┌──────────────────┐    ┌───────────────────┐ │
│  │   Ghidra     │    │  Claude / LLM    │    │ Docker Container  │ │
│  │   (GUI)      │    │  (MCP Client)    │    │ (linux/amd64)     │ │
│  │   :8080      │    │                  │    │                   │ │
│  └──────┬───────┘    └────────┬─────────┘    │  GDB + GEF       │ │
│         │                     │              │  Frida            │ │
│         │     MCP Protocol    │              │  pwntools         │ │
│         │          │          │              │  ropper           │ │
│         │          ▼          │              │  angr             │ │
│         │  ┌────────────────┐ │              │  pyelftools       │ │
│         └─►│  MCP Bridge    │◄┘              │  z3-solver        │ │
│            │  (Python)      │◄──── HTTP ────►│  :5000            │ │
│            │  bridge_mcp_   │                │                   │ │
│            │  ghidra.py     │                └───────────────────┘ │
│            └────────────────┘                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Key Files

| File | Purpose |
|------|---------|
| `bridge_mcp_ghidra.py` | MCP server bridge — exposes 100+ tools to LLM clients |
| `trajectory_recorder.py` | Records analysis sessions as JSONL for replay/training |
| `docker/gdb_server.py` | Flask HTTP API inside Docker for dynamic analysis |
| `docker/Dockerfile` | Container with GDB, GEF, Frida, pwntools, and more |
| `docker/docker-compose.yml` | Container orchestration (ports, volumes, caps) |
| `src/main/java/.../GhidraMCPPlugin.java` | Ghidra plugin that serves HTTP API |

## Tool Categories

### Static Analysis (Ghidra — requires running Ghidra instance)

**Triage & exploration:**
- `list_functions()`, `list_imports()`, `list_exports()`, `list_strings()`
- `search_functions_by_name(query)` — fuzzy search
- `list_undefined_functions()` — functions needing analysis (FUN_*, thunk_*)
- `get_program_info()` — architecture, format, hashes, statistics

**Decompilation & disassembly:**
- `decompile_function(name)` / `decompile_function_by_address(address)`
- `disassemble_function(address)`
- `get_bytes(address, length)` — raw hex dump

**Cross-references & call flow:**
- `get_xrefs_to(address)` / `get_xrefs_from(address)`
- `get_callers(name)` / `get_callees(name)`
- `get_call_graph(name, depth)` — full call graph (1-5 levels)
- `get_function_cfg_info(address)` — cyclomatic complexity, basic blocks

**Annotation:**
- `rename_function(old, new)` / `rename_function_by_address(addr, new)`
- `rename_variable(func, old, new)` / `rename_variable_by_address(addr, old, new)`
- `batch_rename(json_operations)` — bulk rename in one call
- `set_decompiler_comment(addr, comment)` / `set_disassembly_comment(addr, comment)`
- `set_function_prototype(addr, prototype)` / `set_local_variable_type(addr, var, type)`

**Type system:**
- `create_struct(name, size)` / `add_struct_field(struct, type, name, offset)`
- `create_enum(name, size)` / `add_enum_member(enum, member, value)`
- `list_data_types()` / `get_struct_fields(name)`

**Patching:**
- `patch_bytes(address, hex)` / `patch_instruction(address, asm)`
- `nop_region(start, end)`
- `export_binary(path, format)` — export patched binary
- `save_program()` — persist all changes in Ghidra project

### Dynamic Analysis (Docker — requires running container)

**Binary management:**
- `gdb_upload_binary(local_path)` / `gdb_list_binaries()`
- `gdb_file_info(binary)` — type, size, hashes, arch
- `gdb_check_arch(binary)` — architecture detection + QEMU info

**Execution & debugging:**
- `gdb_run_binary(binary, args, stdin, timeout)` — run and capture output
- `gdb_execute(binary, commands)` — raw GDB commands
- `gdb_breakpoint_run(binary, breakpoints, stdin)` — breakpoint + state capture
- `gdb_step_execution(binary, breakpoint, command, count)` — stepi/nexti/step/next
- `gdb_read_registers(binary, breakpoint)` — full register dump
- `gdb_read_memory(binary, address, length, format)` — memory inspection
- `gdb_inspect_stack(binary, breakpoint, depth)` — stack frames + memory
- `gdb_set_watchpoint(binary, expression, type)` — hardware watchpoints
- `gdb_analyze_heap(binary, breakpoint)` — GEF heap analysis
- `gdb_vmmap(binary, breakpoint)` — virtual memory map
- `gdb_search_pattern(binary, pattern, breakpoint)` — pattern search in memory

**Tracing & instrumentation:**
- `gdb_strace(binary)` / `gdb_ltrace(binary)` — syscall/library tracing
- `gdb_frida_instrument(binary, script)` — run Frida JS script
- `gdb_frida_trace(binary, functions)` — trace function calls with Frida
- `gdb_frida_hook(binary, target, on_enter, on_leave)` — intercept functions

**Binary analysis:**
- `gdb_checksec(binary)` — NX, PIE, RELRO, canary
- `gdb_pe_info(binary)` — PE (Windows) structure, sections, imports, exports
- `gdb_disassemble(binary, symbol)` — objdump disassembly
- `gdb_strings(binary)` / `gdb_sections(binary)` / `gdb_symbols(binary)`
- `gdb_entropy(binary)` — packing/encryption detection
- `gdb_binwalk(binary)` — embedded file detection
- `gdb_got_plt(binary)` — GOT/PLT inspection
- `gdb_rop_gadgets(binary, max_depth, filter)` — ROP gadget finding
- `gdb_patch_elf(binary, address, bytes)` — patch ELF at virtual address

**Angr symbolic execution (headless):**
- `angr_explore(binary, find_addr)` — find stdin that reaches target address
- `angr_cfg(binary)` — control flow graph (nodes, edges)
- `angr_entry(binary)` — entry point and main address
- `gdb_angr_selftest(timeout)` — verify angr runtime/symbolic execution is healthy

**Autonomous:**
- `auto_triage(binary)` — run full triage pipeline (file_info, checksec, entropy, imports, strings)

### Trajectory Recording

- `trajectory_start(binary_name)` — begin recording session
- `trajectory_stop(summary)` — end recording
- `trajectory_note(note, category)` — add observations during analysis
- `trajectory_status()` / `trajectory_list()` — session management
- `trajectory_analyze(path)` / `trajectory_export_markdown(path)` — post-analysis
- `analysis_session_recap(...)` — full write-up with tool timeline + terminal snapshots

### Observability / Telemetry

- `gdb_get_telemetry(lines)` — recent GDB API tool calls
- `gdb_get_command_telemetry(lines)` — command history with stdout/stderr snapshots
- `trajectory_log_llm_turn(role, content, metadata_json)` — log LLM/user conversational turns
- `trajectory_assert_logging(...)` — enforce minimum logging completeness

## Agent Logging SOP

Follow the session contract in:

- `docs/AGENT_OBSERVABILITY_INSTRUCTIONS.md`

## Typical RE Workflow

### Phase 1: Triage
```
1. get_program_info()                    → architecture, format, basic stats
2. gdb_checksec(binary)                  → security mitigations
3. list_imports() + list_exports()       → API surface
4. list_strings(filter="flag")           → interesting strings
5. gdb_entropy(binary)                   → check for packing
```

### Phase 2: Static Analysis
```
1. list_undefined_functions()            → prioritize analysis targets
2. decompile_function(name)              → understand logic
3. get_call_graph(name, depth=2)         → map relationships
4. get_function_cfg_info(address)        → assess complexity
5. get_xrefs_to(address)                 → find usage patterns
```

### Phase 3: Dynamic Analysis
```
1. gdb_breakpoint_run(binary, ["main"])  → initial execution state
2. gdb_read_registers(binary, "main")    → register values
3. gdb_strace(binary)                    → system call behavior
4. gdb_frida_trace(binary, ["malloc", "free", "memcpy"])  → memory ops
5. gdb_read_memory(binary, addr, 256)    → inspect runtime data
```

### Phase 4: Annotation & Patching
```
1. batch_rename([...])                   → rename functions/variables
2. set_decompiler_comment(addr, note)    → annotate findings
3. create_struct("PacketHeader", 32)     → define data types
4. patch_instruction(addr, "NOP")        → modify behavior
5. export_binary("/tmp/patched")         → export result
```

## Setup for Competition

### Quick Start
```bash
# 1. Start Ghidra, load binary, enable GhidraMCPPlugin
# 2. Start Docker container for dynamic analysis
cd docker && docker-compose up -d --build

# 3. Verify connectivity
curl http://127.0.0.1:8080/methods    # Ghidra plugin
curl http://127.0.0.1:5000/health     # GDB container

# 4. Run MCP bridge (for Claude Desktop / Cline)
python bridge_mcp_ghidra.py --transport stdio
```

### MCP Client Configuration (Claude Desktop)
```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/path/to/bridge_mcp_ghidra.py",
        "--ghidra-server", "http://127.0.0.1:8080/",
        "--gdb-server", "http://127.0.0.1:5000/"
      ]
    }
  }
}
```

## Important Notes

- **Pagination**: Many list tools support `offset`/`limit` params. Use them for large binaries.
- **Address format**: Use hex strings like `"0x401000"`. The `0x` prefix is required.
- **Binary names**: For GDB tools, use just the filename (e.g., `"chall"`), not the full path.
- **Trajectory recording**: Start recording before analysis to capture replayable sessions.
- **Ghidra must be running**: Static analysis tools require Ghidra with the plugin active.
- **Docker must be running**: Dynamic analysis tools require the GDB container.
- **Multi-arch**: The container supports x86_64, ARM, MIPS, PowerPC, RISC-V via QEMU.

## Development

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all checks (lint + typecheck + tests)
./scripts/check.sh

# Auto-fix lint issues
./scripts/check.sh --fix

# Quick mode (skip slow checks)
./scripts/check.sh --quick

# Run just tests
python -m pytest tests/ -v

# Run just linter
ruff check .

# Set up pre-commit hooks
pre-commit install
```
