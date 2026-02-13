# Agent Observability Instructions

This guide defines the minimum logging contract for AI agents (Claude Desktop/CLI, Cursor, etc.)
when using `bridge_mcp_ghidra.py` with trajectory recording.

## Goal

Produce audit-grade traces that answer:

- What commands/tools ran?
- What did they return?
- What did the model decide/say?
- Why did analysis stop/succeed/fail?

## Required Session Contract

1. **Start session**
   - Call `trajectory_start(binary_name)` before analysis.
2. **Log major LLM turns**
   - After each major assistant response (plan, hypothesis, finding, pivot), call:
     - `trajectory_log_llm_turn(role="assistant", content=..., metadata_json=...)`
   - Optionally log user turns with `role="user"`.
3. **Add analyst notes**
   - Use `trajectory_note(note, category)` for important observations.
4. **Validate logging completeness**
   - Call `trajectory_assert_logging(min_llm_turns=1, min_tool_calls=1)` before stopping.
5. **End session**
   - Call `trajectory_stop(summary)`.
6. **Export recap**
   - Call `analysis_session_recap(output_path=...)`.

## Metadata Recommendations

For `trajectory_log_llm_turn(..., metadata_json=...)`, include:

```json
{
  "model": "claude-<variant>",
  "tokens_in": 1234,
  "tokens_out": 456,
  "phase": "triage|static|dynamic|patching|validation"
}
```

## Operational Verification

- Tool telemetry: `gdb_get_telemetry(lines=200)`
- Command telemetry (with stdout/stderr snapshots): `gdb_get_command_telemetry(lines=200)`
- Session recap markdown: `analysis_session_recap(...)`

## angr Validation

Before using `angr_explore` in a live task, run:

- `gdb_angr_selftest(timeout=30)`

Expected: `ok=true`, `found_states>=1`, and a symbolic stdin solution (typically starts with `"A"`).
