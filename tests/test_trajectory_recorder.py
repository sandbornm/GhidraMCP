"""
Tests for the GhidraMCP trajectory recording system (trajectory_recorder.py).

Tests cover recording, analysis, export, and edge cases of the trajectory system.
"""

import json
import os
import sys
import tempfile
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trajectory_recorder import (
    TrajectoryRecorder,
    analyze_trajectory,
    export_trajectory_markdown,
    get_recorder,
    init_recorder,
    record_tool_call,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_dir():
    """Create a temporary directory for trajectory files."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def recorder(tmp_dir):
    """Create a TrajectoryRecorder with a temporary directory."""
    return TrajectoryRecorder(output_dir=tmp_dir, binary_name="test_binary")


@pytest.fixture
def populated_trajectory(tmp_dir):
    """Create a trajectory with several recorded tool calls."""
    rec = TrajectoryRecorder(output_dir=tmp_dir, binary_name="test_binary")

    # Record various tool calls
    rec.record("list_functions", {}, ["main", "helper"], 50.0, True)
    rec.record("decompile_function", {"name": "main"},
               "int main() { return 0; }", 150.0, True)
    rec.record("rename_function", {"old_name": "FUN_001", "new_name": "decrypt"},
               "Renamed successfully", 30.0, True)
    rec.record("patch_bytes", {"address": "0x401000", "bytes": "90 90"},
               "Patched 2 bytes", 25.0, True)
    rec.record("gdb_run_binary", {"binary": "test"}, {"stdout": "ok"}, 200.0, True)
    rec.record("unknown_tool", {}, "result", 10.0, True)
    rec.record("decompile_function", {"name": "broken"},
               "Decompilation failed", 100.0, False)

    rec.add_note("Found interesting function at 0x401000", "finding")
    rec.end_session("Test session completed")

    return rec.get_session_path()


# ===========================================================================
# Tests for TrajectoryRecorder initialization
# ===========================================================================

class TestRecorderInit:
    def test_basic_init(self, tmp_dir):
        rec = TrajectoryRecorder(output_dir=tmp_dir, binary_name="mybin")
        assert rec.binary_name == "mybin"
        assert rec.session_id is not None
        assert len(rec.session_id) > 0
        assert rec.get_session_path().exists()

    def test_default_binary_name(self, tmp_dir):
        rec = TrajectoryRecorder(output_dir=tmp_dir)
        assert rec.binary_name == "unknown"

    def test_creates_output_dir(self):
        with tempfile.TemporaryDirectory() as base:
            subdir = os.path.join(base, "nested", "deep")
            TrajectoryRecorder(output_dir=subdir, binary_name="test")
            assert os.path.isdir(subdir)

    def test_session_start_written(self, recorder):
        path = recorder.get_session_path()
        with open(path) as f:
            first_line = json.loads(f.readline())
        assert first_line["type"] == "session_start"
        assert first_line["binary"] == "test_binary"
        assert first_line["session_id"] == recorder.session_id

    def test_unique_session_ids(self, tmp_dir):
        rec1 = TrajectoryRecorder(output_dir=tmp_dir, binary_name="a")
        rec2 = TrajectoryRecorder(output_dir=tmp_dir, binary_name="b")
        assert rec1.session_id != rec2.session_id


# ===========================================================================
# Tests for recording tool calls
# ===========================================================================

class TestRecording:
    def test_record_tool_call(self, recorder):
        recorder.record("decompile_function", {"name": "main"},
                        "int main() { return 0; }", 150.5, True)

        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert len(tool_calls) == 1
        assert tool_calls[0]["tool"] == "decompile_function"
        assert tool_calls[0]["category"] == "static_analysis"
        assert tool_calls[0]["duration_ms"] == 150.5
        assert tool_calls[0]["success"] is True

    def test_record_categorization(self, recorder):
        test_cases = [
            ("list_methods", "static_analysis"),
            ("rename_function", "annotation"),
            ("patch_bytes", "patching"),
            ("gdb_run_binary", "dynamic_analysis"),
            ("export_binary", "file_ops"),
            ("gdb_health", "system"),
            ("get_current_address", "navigation"),
            ("rename_variable_by_address", "annotation"),
            ("batch_rename", "annotation"),
            ("get_call_graph", "static_analysis"),
            ("list_undefined_functions", "static_analysis"),
            ("get_function_cfg_info", "static_analysis"),
            ("totally_unknown", "unknown"),
        ]

        for tool, _expected_cat in test_cases:
            recorder.record(tool, {}, "result", 10.0, True)

        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]

        for i, (tool, expected_cat) in enumerate(test_cases):
            assert tool_calls[i]["category"] == expected_cat, \
                f"Tool {tool} expected category {expected_cat}, got {tool_calls[i]['category']}"

    def test_record_failed_call(self, recorder):
        recorder.record("decompile_function", {"name": "nonexistent"},
                        "Function not found", 50.0, False)
        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert tool_calls[0]["success"] is False

    def test_record_address_extraction_from_params(self, recorder):
        recorder.record("patch_bytes",
                        {"address": "0x401000", "bytes": "90"},
                        "Patched", 20.0, True)
        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert "0x401000" in tool_calls[0]["address_context"]

    def test_record_address_extraction_from_result(self, recorder):
        recorder.record("get_xrefs_to", {"address": "0x401000"},
                        "From 0x402000 in main [CALL]\nFrom 0x403000 [DATA]",
                        30.0, True)
        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        addrs = tool_calls[0]["address_context"]
        assert "0x401000" in addrs
        assert "0x402000" in addrs

    def test_record_full_result_for_patching(self, recorder):
        recorder.record("patch_bytes",
                        {"address": "0x401000"},
                        "Patched 2 bytes at 0x401000",
                        20.0, True)
        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert "result" in tool_calls[0]

    def test_record_no_full_result_for_static_analysis(self, recorder):
        recorder.record("list_functions", {},
                        "func1\nfunc2\nfunc3",
                        20.0, True)
        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert "result" not in tool_calls[0]

    def test_result_summarization_string(self, recorder):
        recorder.record("decompile_function", {"name": "main"},
                        "line1\nline2\nline3", 50.0, True)
        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert "3 lines" in tool_calls[0]["result_summary"]

    def test_result_summarization_list(self, recorder):
        recorder.record("list_functions", {},
                        ["f1", "f2", "f3"], 50.0, True)
        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert "3 items" in tool_calls[0]["result_summary"]

    def test_result_summarization_dict_error(self, recorder):
        recorder.record("gdb_health", {},
                        {"error": "Connection refused to server"}, 50.0, False)
        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert "Error:" in tool_calls[0]["result_summary"]

    def test_result_summarization_dict_normal(self, recorder):
        recorder.record("gdb_health", {},
                        {"status": "ok", "platform": "linux"}, 50.0, True)
        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert "2 keys" in tool_calls[0]["result_summary"]


# ===========================================================================
# Tests for notes
# ===========================================================================

class TestNotes:
    def test_add_note(self, recorder):
        recorder.add_note("Found buffer overflow", "finding")
        entries = _read_entries(recorder.get_session_path())
        notes = [e for e in entries if e["type"] == "note"]
        assert len(notes) == 1
        assert notes[0]["note"] == "Found buffer overflow"
        assert notes[0]["category"] == "finding"

    def test_add_note_default_category(self, recorder):
        recorder.add_note("Something interesting")
        entries = _read_entries(recorder.get_session_path())
        notes = [e for e in entries if e["type"] == "note"]
        assert notes[0]["category"] == "observation"


# ===========================================================================
# Tests for session management
# ===========================================================================

class TestSessionManagement:
    def test_end_session(self, recorder):
        recorder.record("list_functions", {}, ["f1"], 10.0, True)
        recorder.end_session("Analysis complete")

        entries = _read_entries(recorder.get_session_path())
        session_end = [e for e in entries if e["type"] == "session_end"]
        assert len(session_end) == 1
        assert session_end[0]["summary"] == "Analysis complete"
        assert session_end[0]["duration_seconds"] >= 0

    def test_set_binary(self, recorder):
        recorder.set_binary("new_binary")
        assert recorder.binary_name == "new_binary"

        entries = _read_entries(recorder.get_session_path())
        changes = [e for e in entries if e["type"] == "binary_change"]
        assert len(changes) == 1
        assert changes[0]["binary"] == "new_binary"

    def test_session_file_path(self, recorder):
        path = recorder.get_session_path()
        assert path.suffix == ".jsonl"
        assert recorder.session_id in path.name


# ===========================================================================
# Tests for thread safety
# ===========================================================================

class TestThreadSafety:
    def test_concurrent_recording(self, tmp_dir):
        rec = TrajectoryRecorder(output_dir=tmp_dir, binary_name="concurrent_test")
        errors = []

        def record_batch(thread_id):
            try:
                for i in range(20):
                    rec.record(f"tool_{thread_id}_{i}", {"i": i},
                               f"result_{i}", float(i), True)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=record_batch, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

        entries = _read_entries(rec.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert len(tool_calls) == 100  # 5 threads * 20 calls


# ===========================================================================
# Tests for analyze_trajectory
# ===========================================================================

class TestAnalyzeTrajectory:
    def test_basic_analysis(self, populated_trajectory):
        analysis = analyze_trajectory(str(populated_trajectory))
        assert analysis["binary"] == "test_binary"
        assert analysis["total_tool_calls"] == 7  # 6 calls + 1 unknown

    def test_tool_counts(self, populated_trajectory):
        analysis = analyze_trajectory(str(populated_trajectory))
        assert analysis["tool_counts"]["decompile_function"] == 2
        assert analysis["tool_counts"]["patch_bytes"] == 1

    def test_category_counts(self, populated_trajectory):
        analysis = analyze_trajectory(str(populated_trajectory))
        # list_functions (static) + 2x decompile_function (static) = 3
        assert analysis["category_counts"]["static_analysis"] == 3
        assert analysis["category_counts"]["annotation"] == 1
        assert analysis["category_counts"]["patching"] == 1

    def test_patches_tracked(self, populated_trajectory):
        analysis = analyze_trajectory(str(populated_trajectory))
        assert len(analysis["patches_applied"]) == 1
        assert analysis["patches_applied"][0]["tool"] == "patch_bytes"

    def test_errors_tracked(self, populated_trajectory):
        analysis = analyze_trajectory(str(populated_trajectory))
        assert len(analysis["errors"]) == 1
        assert analysis["errors"][0]["tool"] == "decompile_function"

    def test_notes_included(self, populated_trajectory):
        analysis = analyze_trajectory(str(populated_trajectory))
        assert len(analysis["notes"]) == 1
        assert "interesting function" in analysis["notes"][0]["note"]

    def test_session_duration(self, populated_trajectory):
        analysis = analyze_trajectory(str(populated_trajectory))
        assert analysis["session_duration_seconds"] is not None
        assert analysis["session_duration_seconds"] >= 0

    def test_addresses_collected(self, populated_trajectory):
        analysis = analyze_trajectory(str(populated_trajectory))
        assert analysis["unique_addresses"] >= 1


# ===========================================================================
# Tests for export_trajectory_markdown
# ===========================================================================

class TestExportMarkdown:
    def test_export_to_string(self, populated_trajectory):
        md = export_trajectory_markdown(str(populated_trajectory))
        assert "# Reverse Engineering Trajectory" in md
        assert "test_binary" in md
        assert "## Summary" in md
        assert "## Analysis Timeline" in md

    def test_export_to_file(self, populated_trajectory, tmp_dir):
        output_path = os.path.join(tmp_dir, "report.md")
        export_trajectory_markdown(str(populated_trajectory), output_path)
        assert os.path.exists(output_path)
        with open(output_path) as f:
            content = f.read()
        assert "# Reverse Engineering Trajectory" in content

    def test_export_contains_patches(self, populated_trajectory):
        md = export_trajectory_markdown(str(populated_trajectory))
        assert "Patches Applied" in md

    def test_export_contains_notes(self, populated_trajectory):
        md = export_trajectory_markdown(str(populated_trajectory))
        assert "Notes" in md

    def test_export_contains_timeline(self, populated_trajectory):
        md = export_trajectory_markdown(str(populated_trajectory))
        assert "decompile_function" in md
        assert "patch_bytes" in md


# ===========================================================================
# Tests for global recorder functions
# ===========================================================================

class TestGlobalRecorder:
    def test_get_recorder_none_by_default(self):
        # Reset global state
        import trajectory_recorder
        trajectory_recorder._recorder = None
        assert get_recorder() is None

    def test_init_recorder(self, tmp_dir):
        import trajectory_recorder
        rec = init_recorder(output_dir=tmp_dir, binary_name="global_test")
        assert rec is not None
        assert get_recorder() is rec
        assert rec.binary_name == "global_test"
        # Clean up
        trajectory_recorder._recorder = None


# ===========================================================================
# Tests for record_tool_call decorator
# ===========================================================================

class TestRecordToolCallDecorator:
    def test_decorator_without_recorder(self):
        import trajectory_recorder
        trajectory_recorder._recorder = None

        @record_tool_call
        def my_tool(x=1):
            return x + 1

        result = my_tool(x=5)
        assert result == 6

    def test_decorator_with_recorder(self, tmp_dir):
        import trajectory_recorder
        rec = init_recorder(output_dir=tmp_dir, binary_name="decorator_test")

        @record_tool_call
        def my_tool(name="test"):
            return f"result_{name}"

        result = my_tool(name="hello")
        assert result == "result_hello"

        entries = _read_entries(rec.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert len(tool_calls) == 1
        assert tool_calls[0]["tool"] == "my_tool"

        # Clean up
        trajectory_recorder._recorder = None

    def test_decorator_records_failure(self, tmp_dir):
        import trajectory_recorder
        rec = init_recorder(output_dir=tmp_dir, binary_name="fail_test")

        @record_tool_call
        def failing_tool():
            raise ValueError("test error")

        with pytest.raises(ValueError):
            failing_tool()

        entries = _read_entries(rec.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert len(tool_calls) == 1
        assert tool_calls[0]["success"] is False

        # Clean up
        trajectory_recorder._recorder = None


# ===========================================================================
# Tests for edge cases
# ===========================================================================

class TestEdgeCases:
    def test_empty_trajectory(self, tmp_dir):
        rec = TrajectoryRecorder(output_dir=tmp_dir, binary_name="empty")
        rec.end_session()
        analysis = analyze_trajectory(str(rec.get_session_path()))
        assert analysis["total_tool_calls"] == 0

    def test_very_long_result(self, recorder):
        long_result = "x" * 20000
        recorder.record("list_functions", {}, long_result, 10.0, True)
        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        # Should still have a summary
        assert "result_summary" in tool_calls[0]

    def test_special_characters_in_params(self, recorder):
        recorder.record("rename_function",
                        {"old_name": "func<test>&\"'", "new_name": "new_func"},
                        "ok", 10.0, True)
        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert tool_calls[0]["params"]["old_name"] == "func<test>&\"'"

    def test_none_result(self, recorder):
        recorder.record("some_tool", {}, None, 10.0, True)
        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert "result_summary" in tool_calls[0]

    def test_address_extraction_limits(self, recorder):
        # Result with many addresses - should be limited to 5
        result = " ".join([f"0x{i:08x}" for i in range(20)])
        recorder.record("search", {}, result, 10.0, True)
        entries = _read_entries(recorder.get_session_path())
        tool_calls = [e for e in entries if e["type"] == "tool_call"]
        assert len(tool_calls[0]["address_context"]) <= 5 + 1  # params + result addresses


# ===========================================================================
# Helper
# ===========================================================================

def _read_entries(path):
    """Read all JSONL entries from a trajectory file."""
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries
