[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# ghidraMCP
ghidraMCP is an Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes numerous tools from core Ghidra functionality to MCP clients.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9


# Features
MCP Server + Ghidra Plugin

- Decompile and analyze binaries in Ghidra
- Automatically rename methods and data
- List methods, classes, imports, and exports

## Semi-Autonomous Reverse Engineering

GhidraMCP provides 105+ MCP tools across static analysis, dynamic analysis, annotation, and patching to enable LLM-driven reverse engineering. Key capability areas:

### Decompilation & Rename

Rename functions and variables directly in the decompilation view to improve readability:

- **`rename_variable_by_address`** - Rename local variables in a function identified by address (more reliable than by name for auto-generated function names like `FUN_00401000`)
- **`batch_rename`** - Rename multiple functions, variables, and data labels in a single operation for efficient annotation
- **`rename_function`** / **`rename_function_by_address`** - Rename functions by name or address
- **`rename_variable`** - Rename local variables within a function by name
- **`rename_data`** - Rename data labels at specific addresses

### Analysis & Triage

Tools for prioritizing and understanding functions during autonomous analysis:

- **`get_call_graph`** - Get a complete call graph (both callers and callees) with configurable depth (1-5 levels)
- **`list_undefined_functions`** - Find functions with auto-generated names (FUN_\*, thunk_\*) that need analysis, sorted by metadata (size, caller count, parameters)
- **`get_function_cfg_info`** - Get control flow metrics including basic block count, cyclomatic complexity, branch count, and complexity classification
- **`search_functions_by_name`** - Fuzzy search for functions by substring

### Angr Symbolic Execution & Autonomous Triage

Headless symbolic execution and automated analysis pipelines:

- **`angr_explore`** - Find stdin input that reaches a target address via symbolic execution
- **`angr_cfg`** - Control flow graph (nodes, edges) from angr
- **`angr_entry`** - Entry point and main symbol addresses
- **`gdb_angr_selftest`** - Runtime health/self-test for angr loading + symbolic exploration
- **`auto_triage`** - Run full triage pipeline (file_info, checksec, entropy, imports, strings) in one call
- **`gdb_pe_info`** - PE (Windows) binary structure, sections, imports, exports

### Dynamic Analysis & Instrumentation

Full runtime debugging via GDB/GEF Docker container with Frida instrumentation:

- **`gdb_read_registers`** - Dump all CPU registers at any breakpoint
- **`gdb_read_memory`** - Read memory as hex, strings, or disassembly
- **`gdb_step_execution`** - Single-step (stepi/nexti/step/next) with state capture
- **`gdb_set_watchpoint`** - Hardware watchpoints for write/read/access
- **`gdb_inspect_stack`** - Full stack frame inspection with backtrace
- **`gdb_analyze_heap`** - GEF-powered heap analysis (chunks, bins, arenas)
- **`gdb_vmmap`** - Virtual memory map with permissions
- **`gdb_search_pattern`** - Search for patterns in process memory
- **`gdb_rop_gadgets`** - Find ROP gadgets for exploit development
- **`gdb_got_plt`** - Inspect GOT/PLT entries
- **`gdb_capture_pcap`** / **`gdb_analyze_pcap`** / **`gdb_list_pcaps`** - Capture and analyze network traffic PCAPs with tcpdump/tshark
- **`gdb_frida_instrument`** / **`gdb_frida_trace`** / **`gdb_frida_hook`** - Frida-based function tracing and hooking

### Observability & Recap

Visibility tools for understanding what happened during an analysis session:

- **`gdb_get_telemetry`** - Recent MCP tool calls to the GDB server
- **`gdb_get_command_telemetry`** - Subprocess command history with stdout/stderr snapshots
- **`trajectory_log_llm_turn`** - Explicitly log assistant/user turns into trajectory
- **`trajectory_assert_logging`** - Guardrail to verify minimum logging completeness
- **`analysis_session_recap`** - Generate a markdown write-up including timeline, commands, and terminal snapshots

### Full Tool Categories

| Category | Count | Examples |
|----------|-------|---------|
| Static Analysis | 30+ | decompile, disassemble, xrefs, call graphs, strings, CFG info |
| Annotation | 10+ | rename functions/variables/data, comments, prototypes, type system |
| Type System | 6 | create/inspect structures, enums, set variable types |
| Patching | 7 | patch bytes/instructions, NOP regions, export binary |
| Navigation | 5 | goto address, bookmarks, current selection |
| Dynamic Analysis (GDB) | 35+ | registers, memory, stepping, watchpoints, heap, vmmap, ROP gadgets |
| Frida Instrumentation | 3 | instrument, trace, hook function calls |
| Trajectory Recording | 7 | record, analyze, export analysis sessions |
| Observability | 3 | tool telemetry, command telemetry, analysis recap |

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, download the latest [release](https://github.com/LaurieWired/GhidraMCP/releases) from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-2.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`
7. *Optional*: Configure the port in Ghidra with `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`

## Python Bridge Commands

Use `uv` to run the Python MCP bridges from this checkout:

```bash
uv sync --extra dev
uv run ghidra-mcp --help
uv run ghidra-mcp-static --help
uv run ghidra-mcp-gdb --help
```

For local symbolic-execution helpers outside the Docker service, include
`uv sync --extra symbolic`.

The console commands map to the legacy bridge files:

- `ghidra-mcp`: combined Ghidra + GDB MCP bridge.
- `ghidra-mcp-static`: static Ghidra bridge with optional GDB interop.
- `ghidra-mcp-gdb`: dedicated GDB/Docker dynamic analysis bridge.

## Headless Multi-Process Setup (One Binary Per Agent)

If you want true concurrency (one Ghidra process per binary / per agent), see `docs/HEADLESS_FARM.md`.
This approach spawns isolated `analyzeHeadless` processes, each running a long-lived HTTP API server on its own port.
For Mac mini setup + update instructions, see `docs/MAC_MINI_HEADLESS_SETUP.md`.

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with ghidraMCP.  Three examples are given below.

## Example 1: Claude Desktop
To set up Claude Desktop as a Ghidra MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "uv",
      "args": [
        "--directory",
        "/ABSOLUTE_PATH_TO/GhidraMCP",
        "run",
        "ghidra-mcp",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

The server IP and port are configurable and should be set to point to the target Ghidra instance. If not set, both will default to localhost:8080.

## Example 2: Cline
To use GhidraMCP with [Cline](https://cline.bot), this requires manually running the MCP server as well. First run the following command:

```
uv run ghidra-mcp --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

The only *required* argument is the transport. If all other arguments are unspecified, they will default to the above. Once the MCP server is running, open up Cline and select `MCP Servers` at the top.

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

Then select `Remote Servers` and add the following, ensuring that the url matches the MCP host and port:

1. Server Name: GhidraMCP
2. Server URL: `http://127.0.0.1:8081/sse`

## Example 3: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `uv --directory /ABSOLUTE_PATH_TO/GhidraMCP run ghidra-mcp`

# Testing

The project includes a comprehensive Python test suite with 199 tests.

## Running Tests

```bash
# With uv (recommended)
uv sync --extra dev
uv run pytest tests/ -v

# Or with pip
pip install -r requirements-dev.txt
python -m pytest tests/ -v

# Run just unit tests (fast)
uv run pytest tests/ -v -m "not integration and not slow"

# Run with coverage
uv run pytest tests/ --cov=bridge_mcp_ghidra --cov=trajectory_recorder --cov-report=term-missing

# Run the full check script (lint + typecheck + tests)
./scripts/check.sh

# Auto-fix lint issues
./scripts/check.sh --fix
```

The test suite includes 199 tests covering:

- **MCP Bridge (`test_bridge_mcp_ghidra.py`)** - 95+ unit tests for MCP tools with mocked HTTP responses
- **Enhanced GDB Tools (`test_enhanced_gdb_tools.py`)** - 30+ tests for registers, memory, stepping, watchpoints, Frida, ROP gadgets, PE tools, angr tools, and autonomous triage.
- **Integration Tests (`test_integration.py`)** - 20 tests for multi-tool workflows (triage, analysis, patching, error recovery)
- **Trajectory Recorder (`test_trajectory_recorder.py`)** - 45+ tests for recording, analysis, export, thread safety, and LLM trace logging

Tests mock HTTP responses so they run without live Ghidra/GDB instances.

## CI/CD

GitHub Actions runs automatically on push/PR to main. **All checks must pass before merge** (configure "Merge Gate" as required status in branch protection):

- Linting (ruff) and type checking (mypy)
- Unit tests on Python 3.10, 3.11, 3.12 (uv for dependency install)
- Integration tests
- Java/Maven Ghidra plugin build
- Docker build validation
- Security scanning

## Pre-commit Hooks

```bash
pip install pre-commit
pre-commit install
```

This enables automatic linting, formatting, and type checking on every commit.

# Additional Documentation

- **[AGENTS.md](AGENTS.md)** - Quick-start guide for AI agents working with this toolchain
- **[docs/AGENT_OBSERVABILITY_INSTRUCTIONS.md](docs/AGENT_OBSERVABILITY_INSTRUCTIONS.md)** - Required logging SOP for agent traceability
- **[CLAUDE_CODE_SETUP.md](CLAUDE_CODE_SETUP.md)** - Configuration guide for Claude Code CLI and macOS desktop app
- **[docker/README.md](docker/README.md)** - Docker container setup and API reference

# Building from Source
1. Copy the following files from your Ghidra directory to this project's `lib/` directory:
- `Ghidra/Features/Base/lib/Base.jar`
- `Ghidra/Features/Decompiler/lib/Decompiler.jar`
- `Ghidra/Framework/Docking/lib/Docking.jar`
- `Ghidra/Framework/Generic/lib/Generic.jar`
- `Ghidra/Framework/Project/lib/Project.jar`
- `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
- `Ghidra/Framework/Utility/lib/Utility.jar`
- `Ghidra/Framework/Gui/lib/Gui.jar`
2. Build with Maven by running:

`mvn clean package assembly:single`

The generated zip file includes the built Ghidra plugin and its resources. These files are required for Ghidra to recognize the new extension.

- lib/GhidraMCP.jar
- extensions.properties
- Module.manifest
