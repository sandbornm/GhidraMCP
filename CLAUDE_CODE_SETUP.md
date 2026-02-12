# Claude Code RE Toolchain Configuration Guide

Strategies for configuring Claude Code (CLI and macOS desktop app) to effectively use GhidraMCP for binary reverse engineering competitions and research.

## Overview

GhidraMCP can be used with Claude in two modes:

| Mode | Tool | Transport | Best For |
|------|------|-----------|----------|
| **CLI** | `claude` (terminal) | stdio | Scripted workflows, SSH, headless servers, CI pipelines |
| **Desktop** | Claude Desktop (macOS) | stdio | Interactive analysis, visual feedback, casual RE sessions |

## Claude Code CLI Setup

### Installation

```bash
# Install Claude Code CLI
npm install -g @anthropic-ai/claude-code

# Verify installation
claude --version
```

### MCP Server Configuration

Create or edit `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ghidra-re": {
      "command": "python3",
      "args": [
        "/path/to/GhidraMCP/bridge_mcp_ghidra.py",
        "--ghidra-server", "http://127.0.0.1:8080/",
        "--gdb-server", "http://127.0.0.1:5000/"
      ]
    }
  }
}
```

### CLI Workflow for Competitions

```bash
# Terminal 1: Start Ghidra with plugin (GUI needed for initial setup)
ghidraRun

# Terminal 2: Start the GDB analysis container
cd /path/to/GhidraMCP/docker
docker-compose up -d

# Terminal 3: Use Claude Code CLI directly in your working directory
cd /path/to/challenge/
claude

# Inside Claude Code, you now have all MCP tools available.
# Example prompts:
#   "Analyze the binary 'challenge' - check security, strings, imports"
#   "Decompile the main function and rename variables to be descriptive"
#   "Find the flag validation logic and trace it with Frida"
```

### CLI Advantages for RE

1. **Scriptability**: Pipe binary data, automate analysis chains
2. **SSH/Remote**: Analyze binaries on remote servers directly
3. **Context**: Claude Code sees your local filesystem (challenge files, notes, scripts)
4. **Speed**: Lower latency than desktop for rapid iteration
5. **Integration**: Works with tmux/screen for multi-pane RE setups

### Recommended CLI Workflow

```bash
# Set up a competition workspace
mkdir -p ~/ctf/competition_name/
cd ~/ctf/competition_name/

# Copy challenge binaries
cp ~/Downloads/challenge* .

# Upload to GDB container for dynamic analysis
curl -F "file=@challenge" http://127.0.0.1:5000/upload

# Load the binary in Ghidra (via GUI), then use Claude Code
claude

# Ask Claude to:
# 1. Start trajectory recording for the session
# 2. Perform initial triage (checksec, strings, imports, entropy)
# 3. Identify key functions and rename them
# 4. Trace execution dynamically
# 5. Develop and test exploits
# 6. Export trajectory report when done
```

## macOS Desktop App Setup

### Configuration

1. Open Claude Desktop
2. Go to `Claude` → `Settings` → `Developer` → `Edit Config`
3. Edit `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ghidra-re": {
      "command": "python3",
      "args": [
        "/path/to/GhidraMCP/bridge_mcp_ghidra.py",
        "--ghidra-server", "http://127.0.0.1:8080/",
        "--gdb-server", "http://127.0.0.1:5000/"
      ]
    }
  }
}
```

4. Restart Claude Desktop
5. Verify the MCP tools appear (hammer icon in chat)

### Desktop Advantages for RE

1. **Visual context**: Easily paste screenshots of Ghidra views
2. **Conversation history**: Persistent chat for long analysis sessions
3. **Artifacts**: Claude can render markdown reports, code blocks
4. **Multi-turn**: Natural back-and-forth for iterative analysis
5. **Accessibility**: Lower barrier for team members new to RE

### Desktop Tips

- Keep Ghidra open alongside Claude Desktop for visual cross-referencing
- Use the trajectory recording tools to capture your analysis for team sharing
- Copy hex dumps or decompilation output directly into chat for discussion

## Competition-Optimized Configuration

### Pre-Competition Checklist

```bash
# 1. Verify all services are running
curl -s http://127.0.0.1:8080/methods | head -5    # Ghidra plugin
curl -s http://127.0.0.1:5000/health | jq .         # GDB container

# 2. Run the development checks
cd /path/to/GhidraMCP
./scripts/check.sh --quick

# 3. Pre-warm the Docker container (pulls images, builds)
cd docker && docker-compose up -d --build

# 4. Test a known binary
curl -F "file=@/bin/ls" http://127.0.0.1:5000/upload
curl -s -X POST http://127.0.0.1:5000/checksec \
  -H "Content-Type: application/json" \
  -d '{"binary": "ls"}' | jq .
```

### Recommended Prompt Templates

**Initial triage:**
```
Analyze the binary "challenge". Start a trajectory recording, then:
1. Check security features (checksec)
2. Get file info and architecture
3. List all strings (look for flags, passwords, keys)
4. List imports and exports
5. Check entropy for packing
6. Give me a summary of what this binary likely does
```

**Deep analysis:**
```
Decompile the function at 0x401234. Then:
1. Get the full call graph (depth 3)
2. Get cross-references to understand who calls this
3. Rename all auto-generated variables to meaningful names
4. Add comments explaining the logic
5. Identify any crypto operations or interesting patterns
```

**Dynamic + exploit:**
```
For binary "challenge":
1. Run it with strace to see syscalls
2. Set a breakpoint at the compare function and inspect registers
3. Use Frida to hook strcmp and log its arguments
4. Trace malloc/free to find heap vulnerabilities
5. Find ROP gadgets for building an exploit chain
```

## Multi-Tool Setup (Advanced)

For maximum effectiveness, run Ghidra + Docker + Claude in a tmux session:

```bash
# Create a competition tmux layout
tmux new-session -d -s re

# Pane 0: Ghidra (or file manager)
tmux send-keys -t re 'cd ~/ctf/comp && ls -la' C-m

# Pane 1: Docker logs
tmux split-window -h -t re
tmux send-keys -t re 'cd /path/to/GhidraMCP/docker && docker-compose logs -f' C-m

# Pane 2: Claude Code CLI
tmux split-window -v -t re
tmux send-keys -t re 'cd ~/ctf/comp && claude' C-m

# Attach to the session
tmux attach -t re
```

## Environment Variables

```bash
# Optional: Set default server URLs
export GHIDRA_SERVER="http://127.0.0.1:8080/"
export GDB_SERVER="http://127.0.0.1:5000/"

# Optional: Set trajectory output directory
export GHIDRA_MCP_TRAJECTORY_DIR="~/ctf/trajectories/"
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Cannot connect to Ghidra server" | Ensure Ghidra is running with GhidraMCPPlugin enabled |
| "Cannot connect to GDB server" | Run `docker-compose up -d` in the docker/ directory |
| MCP tools not showing in Claude Desktop | Restart Claude Desktop after editing config |
| Slow Docker operations on ARM Mac | Expected — x86 emulation via QEMU adds overhead |
| GDB timeout on complex binaries | Increase timeout parameter in tool calls |
| Frida fails to attach | Ensure Docker has SYS_PTRACE capability (set in docker-compose.yml) |
| "Binary not found" errors | Upload binary first with `gdb_upload_binary()` or copy to `docker/bins/` |
