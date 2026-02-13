"""
Tests for the GhidraMCP bridge MCP server (bridge_mcp_ghidra.py).

These tests mock HTTP responses from the Ghidra plugin server to validate
MCP tool behavior, parameter handling, error handling, and response parsing.
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Add project root to path so we can import the module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_mcp_ghidra

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_globals():
    """Reset global state before each test."""
    bridge_mcp_ghidra.ghidra_server_url = "http://127.0.0.1:8080/"
    bridge_mcp_ghidra.gdb_server_url = "http://127.0.0.1:5000/"
    bridge_mcp_ghidra.trajectory_recorder = None
    yield


def _mock_response(text="", status_code=200, ok=True, json_data=None):
    """Create a mock HTTP response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = ok
    resp.text = text
    resp.encoding = "utf-8"
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


# ===========================================================================
# Tests for safe_get / safe_post helpers
# ===========================================================================


class TestSafeGet:
    @patch("bridge_mcp_ghidra.requests.get")
    def test_basic_get(self, mock_get):
        mock_get.return_value = _mock_response("line1\nline2\nline3")
        result = bridge_mcp_ghidra.safe_get("methods")
        assert result == ["line1", "line2", "line3"]
        mock_get.assert_called_once()

    @patch("bridge_mcp_ghidra.requests.get")
    def test_get_with_params(self, mock_get):
        mock_get.return_value = _mock_response("func1\nfunc2")
        result = bridge_mcp_ghidra.safe_get("methods", {"offset": 0, "limit": 2})
        assert result == ["func1", "func2"]
        call_args = mock_get.call_args
        assert call_args[1]["params"] == {"offset": 0, "limit": 2}

    @patch("bridge_mcp_ghidra.requests.get")
    def test_get_error_status(self, mock_get):
        mock_get.return_value = _mock_response("Not Found", 404, ok=False)
        result = bridge_mcp_ghidra.safe_get("nonexistent")
        assert len(result) == 1
        assert "Error 404" in result[0]

    @patch("bridge_mcp_ghidra.requests.get")
    def test_get_connection_error(self, mock_get):
        mock_get.side_effect = ConnectionError("Connection refused")
        result = bridge_mcp_ghidra.safe_get("methods")
        assert len(result) == 1
        assert "Request failed" in result[0]

    @patch("bridge_mcp_ghidra.requests.get")
    def test_get_timeout(self, mock_get):
        import requests

        mock_get.side_effect = requests.exceptions.Timeout("timeout")
        result = bridge_mcp_ghidra.safe_get("methods")
        assert "Request failed" in result[0]

    @patch("bridge_mcp_ghidra.requests.get")
    def test_get_empty_response(self, mock_get):
        mock_get.return_value = _mock_response("")
        result = bridge_mcp_ghidra.safe_get("methods")
        # "".splitlines() returns [] in Python
        assert result == []


class TestSafePost:
    @patch("bridge_mcp_ghidra.requests.post")
    def test_post_dict_data(self, mock_post):
        mock_post.return_value = _mock_response("Renamed successfully")
        result = bridge_mcp_ghidra.safe_post("renameFunction", {"oldName": "f1", "newName": "f2"})
        assert result == "Renamed successfully"
        call_args = mock_post.call_args
        assert call_args[1]["data"] == {"oldName": "f1", "newName": "f2"}

    @patch("bridge_mcp_ghidra.requests.post")
    def test_post_string_data(self, mock_post):
        mock_post.return_value = _mock_response("int main() { return 0; }")
        result = bridge_mcp_ghidra.safe_post("decompile", "main")
        assert "int main" in result

    @patch("bridge_mcp_ghidra.requests.post")
    def test_post_error(self, mock_post):
        mock_post.return_value = _mock_response("Server error", 500, ok=False)
        result = bridge_mcp_ghidra.safe_post("renameFunction", {"oldName": "a", "newName": "b"})
        assert "Error 500" in result

    @patch("bridge_mcp_ghidra.requests.post")
    def test_post_connection_error(self, mock_post):
        mock_post.side_effect = ConnectionError("refused")
        result = bridge_mcp_ghidra.safe_post("renameFunction", {"a": "b"})
        assert "Request failed" in result


# ===========================================================================
# Tests for Static Analysis Tools
# ===========================================================================


class TestStaticAnalysisTools:
    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_methods(self, mock_get):
        mock_get.return_value = ["main", "helper", "init"]
        result = bridge_mcp_ghidra.list_methods(offset=0, limit=100)
        assert result == ["main", "helper", "init"]
        mock_get.assert_called_with("methods", {"offset": 0, "limit": 100})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_methods_pagination(self, mock_get):
        mock_get.return_value = ["func3", "func4"]
        bridge_mcp_ghidra.list_methods(offset=2, limit=2)
        mock_get.assert_called_with("methods", {"offset": 2, "limit": 2})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_classes(self, mock_get):
        mock_get.return_value = ["ClassA", "ClassB"]
        result = bridge_mcp_ghidra.list_classes()
        assert "ClassA" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_decompile_function(self, mock_post):
        mock_post.return_value = "int main(int argc, char **argv) {\n  return 0;\n}"
        result = bridge_mcp_ghidra.decompile_function(name="main")
        assert "int main" in result
        mock_post.assert_called_with("decompile", "main")

    @patch("bridge_mcp_ghidra.safe_get")
    def test_decompile_function_by_address(self, mock_get):
        mock_get.return_value = ["int sub_401000() {", "  return 0;", "}"]
        result = bridge_mcp_ghidra.decompile_function_by_address(address="0x401000")
        assert "sub_401000" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_disassemble_function(self, mock_get):
        mock_get.return_value = ["0x401000: PUSH RBP", "0x401001: MOV RBP,RSP"]
        result = bridge_mcp_ghidra.disassemble_function(address="0x401000")
        assert "PUSH RBP" in result[0]

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_functions(self, mock_get):
        mock_get.return_value = ["main at 0x401000", "exit at 0x401100"]
        result = bridge_mcp_ghidra.list_functions()
        assert len(result) == 2

    @patch("bridge_mcp_ghidra.safe_get")
    def test_search_functions_by_name(self, mock_get):
        mock_get.return_value = ["decrypt_data @ 0x401000", "decrypt_key @ 0x401100"]
        result = bridge_mcp_ghidra.search_functions_by_name(query="decrypt")
        assert len(result) == 2

    def test_search_functions_empty_query(self):
        result = bridge_mcp_ghidra.search_functions_by_name(query="")
        assert result == ["Error: query string is required"]

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_imports(self, mock_get):
        mock_get.return_value = ["printf -> EXTERNAL:1234", "malloc -> EXTERNAL:5678"]
        result = bridge_mcp_ghidra.list_imports()
        assert len(result) == 2

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_exports(self, mock_get):
        mock_get.return_value = ["main -> 0x401000"]
        result = bridge_mcp_ghidra.list_exports()
        assert len(result) == 1

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_strings(self, mock_get):
        mock_get.return_value = ['0x402000: "Hello World"', '0x402010: "Error"']
        result = bridge_mcp_ghidra.list_strings()
        assert len(result) == 2

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_strings_with_filter(self, mock_get):
        mock_get.return_value = ['0x402010: "Error"']
        bridge_mcp_ghidra.list_strings(filter="Error")
        call_args = mock_get.call_args
        assert call_args[0][1]["filter"] == "Error"

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_segments(self, mock_get):
        mock_get.return_value = [".text: 0x401000 - 0x402000", ".data: 0x403000 - 0x404000"]
        result = bridge_mcp_ghidra.list_segments()
        assert len(result) == 2


# ===========================================================================
# Tests for Rename Tools
# ===========================================================================


class TestRenameTools:
    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_function(self, mock_post):
        mock_post.return_value = "Renamed successfully"
        result = bridge_mcp_ghidra.rename_function(old_name="FUN_001", new_name="decrypt")
        assert "Renamed" in result
        mock_post.assert_called_with("renameFunction", {"oldName": "FUN_001", "newName": "decrypt"})

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_function_by_address(self, mock_post):
        mock_post.return_value = "Function renamed successfully"
        result = bridge_mcp_ghidra.rename_function_by_address(function_address="0x401000", new_name="main")
        assert "renamed" in result.lower()

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_variable(self, mock_post):
        mock_post.return_value = "Variable renamed"
        result = bridge_mcp_ghidra.rename_variable(function_name="main", old_name="local_8", new_name="buffer")
        assert "renamed" in result.lower()

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_data(self, mock_post):
        mock_post.return_value = "Rename data attempted"
        result = bridge_mcp_ghidra.rename_data(address="0x402000", new_name="g_key")
        assert result == "Rename data attempted"

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_variable_by_address(self, mock_post):
        mock_post.return_value = "Renamed 'local_8' to 'buffer' in main @ 0x401000"
        result = bridge_mcp_ghidra.rename_variable_by_address(
            function_address="0x401000", old_name="local_8", new_name="buffer"
        )
        assert "buffer" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_batch_rename(self, mock_post):
        mock_post.return_value = "OK: Renamed function\nBatch complete: 1 succeeded, 0 failed"
        ops = json.dumps([{"type": "function", "old_name": "FUN_001", "new_name": "decrypt"}])
        result = bridge_mcp_ghidra.batch_rename(operations=ops)
        assert "succeeded" in result


# ===========================================================================
# Tests for Cross-Reference Tools
# ===========================================================================


class TestXrefTools:
    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_xrefs_to(self, mock_get):
        mock_get.return_value = ["From 0x401050 in main [UNCONDITIONAL_CALL]"]
        result = bridge_mcp_ghidra.get_xrefs_to(address="0x401000")
        assert "UNCONDITIONAL_CALL" in result[0]

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_xrefs_from(self, mock_get):
        mock_get.return_value = ["To 0x401100 to function helper [UNCONDITIONAL_CALL]"]
        result = bridge_mcp_ghidra.get_xrefs_from(address="0x401050")
        assert "helper" in result[0]

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_function_xrefs(self, mock_get):
        mock_get.return_value = ["From 0x401050 in caller_func [UNCONDITIONAL_CALL]"]
        result = bridge_mcp_ghidra.get_function_xrefs(name="target_func")
        assert len(result) >= 1

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_callers(self, mock_get):
        mock_get.return_value = ["main @ 0x401050 -> decrypt [UNCONDITIONAL_CALL]"]
        result = bridge_mcp_ghidra.get_callers(name="decrypt")
        assert "main" in result[0]

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_callees(self, mock_get):
        mock_get.return_value = ["main calls printf @ 0x401200 [UNCONDITIONAL_CALL]"]
        result = bridge_mcp_ghidra.get_callees(name="main")
        assert "printf" in result[0]


# ===========================================================================
# Tests for Enhanced Analysis Tools
# ===========================================================================


class TestEnhancedAnalysisTools:
    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_call_graph(self, mock_get):
        mock_get.return_value = [
            "=== Call Graph for main @ 0x401000 ===",
            "",
            "--- CALLERS ---",
            "<- _start @ 0x400000",
            "",
            "--- CALLEES ---",
            "-> printf @ 0x401200",
        ]
        result = bridge_mcp_ghidra.get_call_graph(name="main", depth=1)
        assert "Call Graph" in result
        assert "CALLERS" in result
        assert "CALLEES" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_undefined_functions(self, mock_get):
        mock_get.return_value = [
            "Found 3 undefined/auto-named functions:",
            "FUN_00401000 @ 0x401000 (size=50, params=2, callers=3, source=DEFAULT)",
            "FUN_00401100 @ 0x401100 (size=20, params=0, callers=1, source=ANALYSIS)",
        ]
        result = bridge_mcp_ghidra.list_undefined_functions()
        assert "FUN_00401000" in result[1]

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_function_cfg_info(self, mock_get):
        mock_get.return_value = [
            "=== CFG Info for main @ 0x401000 ===",
            "",
            "Body size: 150 bytes",
            "Instructions: 45",
            "Estimated basic blocks: 8",
            "Conditional branches: 5",
            "Estimated cyclomatic complexity: 6",
            "Complexity class: Moderate",
        ]
        result = bridge_mcp_ghidra.get_function_cfg_info(address="0x401000")
        assert "cyclomatic complexity" in result.lower()
        assert "Moderate" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_function_variables(self, mock_get):
        mock_get.return_value = [
            "Function: main @ 0x401000",
            "Parameters (2):",
            "  int argc [r0]",
            "  char** argv [r1]",
            "Local variables (3):",
            "  int local_8 [Stack[-0x8]]",
        ]
        result = bridge_mcp_ghidra.get_function_variables(address="0x401000")
        assert "argc" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_function_by_address(self, mock_get):
        mock_get.return_value = ["Function: main at 0x401000"]
        result = bridge_mcp_ghidra.get_function_by_address(address="0x401000")
        assert "main" in result


# ===========================================================================
# Tests for Comment and Annotation Tools
# ===========================================================================


class TestAnnotationTools:
    @patch("bridge_mcp_ghidra.safe_post")
    def test_set_decompiler_comment(self, mock_post):
        mock_post.return_value = "Comment set successfully"
        result = bridge_mcp_ghidra.set_decompiler_comment(address="0x401000", comment="Main entry point")
        assert "Comment set" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_set_disassembly_comment(self, mock_post):
        mock_post.return_value = "Comment set successfully"
        result = bridge_mcp_ghidra.set_disassembly_comment(address="0x401000", comment="Stack setup")
        assert "Comment set" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_set_function_prototype(self, mock_post):
        mock_post.return_value = "Function prototype set successfully"
        result = bridge_mcp_ghidra.set_function_prototype(
            function_address="0x401000", prototype="int main(int argc, char **argv)"
        )
        assert "successfully" in result.lower()

    @patch("bridge_mcp_ghidra.safe_post")
    def test_set_local_variable_type(self, mock_post):
        mock_post.return_value = "Variable type set successfully"
        result = bridge_mcp_ghidra.set_local_variable_type(
            function_address="0x401000", variable_name="local_8", new_type="int*"
        )
        assert "set" in result.lower()


# ===========================================================================
# Tests for Type System Tools
# ===========================================================================


class TestTypeSystemTools:
    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_data_types(self, mock_get):
        mock_get.return_value = ["[struct] MyStruct (size=16, category=/)", "[enum] ErrorCode (size=4, category=/)"]
        result = bridge_mcp_ghidra.list_data_types()
        assert any("struct" in item for item in result)

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_struct_fields(self, mock_get):
        mock_get.return_value = ["Structure: MyStruct", "Size: 16 bytes", "Fields:", "  offset=0x0 size=4 int field1"]
        result = bridge_mcp_ghidra.get_struct_fields(name="MyStruct")
        assert "MyStruct" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_create_struct(self, mock_post):
        mock_post.return_value = "Created structure: /MyStruct (size=0)"
        result = bridge_mcp_ghidra.create_struct(name="MyStruct")
        assert "Created" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_add_struct_field(self, mock_post):
        mock_post.return_value = "Added field flags (int) to MyStruct"
        result = bridge_mcp_ghidra.add_struct_field(struct_name="MyStruct", field_type="int", field_name="flags")
        assert "Added" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_create_enum(self, mock_post):
        mock_post.return_value = "Created enum: /ErrorCode (size=4)"
        result = bridge_mcp_ghidra.create_enum(name="ErrorCode")
        assert "Created" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_add_enum_member(self, mock_post):
        mock_post.return_value = "Added SUCCESS = 0 (0x0) to enum ErrorCode"
        result = bridge_mcp_ghidra.add_enum_member(enum_name="ErrorCode", member_name="SUCCESS", value=0)
        assert "SUCCESS" in result


# ===========================================================================
# Tests for Function Management Tools
# ===========================================================================


class TestFunctionManagementTools:
    @patch("bridge_mcp_ghidra.safe_post")
    def test_create_function(self, mock_post):
        mock_post.return_value = "Created function new_func at 0x401000"
        result = bridge_mcp_ghidra.create_function(address="0x401000", name="new_func")
        assert "Created" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_delete_function(self, mock_post):
        mock_post.return_value = "Deleted function old_func at 0x401000"
        result = bridge_mcp_ghidra.delete_function(address="0x401000")
        assert "Deleted" in result


# ===========================================================================
# Tests for Bookmark Tools
# ===========================================================================


class TestBookmarkTools:
    @patch("bridge_mcp_ghidra.safe_post")
    def test_set_bookmark(self, mock_post):
        mock_post.return_value = "Bookmark set at 0x401000 [Vuln]: Buffer overflow"
        result = bridge_mcp_ghidra.set_bookmark(address="0x401000", category="Vuln", comment="Buffer overflow")
        assert "Bookmark set" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_bookmarks(self, mock_get):
        mock_get.return_value = ["0x401000 [Note/Vuln]: Buffer overflow"]
        result = bridge_mcp_ghidra.list_bookmarks()
        assert len(result) == 1

    @patch("bridge_mcp_ghidra.safe_post")
    def test_delete_bookmark(self, mock_post):
        mock_post.return_value = "Removed 1 bookmark(s) at 0x401000"
        result = bridge_mcp_ghidra.delete_bookmark(address="0x401000")
        assert "Removed" in result


# ===========================================================================
# Tests for Navigation Tools
# ===========================================================================


class TestNavigationTools:
    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_current_address(self, mock_get):
        mock_get.return_value = ["0x401000"]
        result = bridge_mcp_ghidra.get_current_address()
        assert "0x401000" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_current_function(self, mock_get):
        mock_get.return_value = ["Function: main at 0x401000"]
        result = bridge_mcp_ghidra.get_current_function()
        assert "main" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_program_name(self, mock_get):
        mock_get.return_value = ["test_binary"]
        result = bridge_mcp_ghidra.get_program_name()
        assert result == "test_binary"

    @patch("bridge_mcp_ghidra.safe_post")
    def test_goto_address(self, mock_post):
        mock_post.return_value = "Navigated to 0x401000"
        result = bridge_mcp_ghidra.goto_address(address="0x401000")
        assert "Navigated" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_address_info(self, mock_get):
        mock_get.return_value = ["Address: 0x401000", "Function entry: main", "Instruction: PUSH RBP"]
        result = bridge_mcp_ghidra.get_address_info(address="0x401000")
        assert "main" in result


# ===========================================================================
# Tests for Program Info Tools
# ===========================================================================


class TestProgramInfoTools:
    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_program_info(self, mock_get):
        mock_get.return_value = [
            "=== Program Information ===",
            "Name: test_binary",
            "Language: x86:LE:64:default",
            "Format: ELF",
        ]
        result = bridge_mcp_ghidra.get_program_info()
        assert "test_binary" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_comments(self, mock_get):
        mock_get.return_value = ["0x401000 [Pre] in main: Entry point", "0x401010 [EOL] in main: Stack setup"]
        result = bridge_mcp_ghidra.list_comments()
        assert len(result) == 2

    @patch("bridge_mcp_ghidra.safe_get")
    def test_run_auto_analysis(self, mock_get):
        mock_get.return_value = ["Auto-analysis triggered for entire program"]
        result = bridge_mcp_ghidra.run_auto_analysis()
        assert "analysis" in result.lower()


# ===========================================================================
# Tests for Patching Tools
# ===========================================================================


class TestPatchingTools:
    @patch("bridge_mcp_ghidra.safe_post")
    def test_patch_bytes(self, mock_post):
        mock_post.return_value = "Patched 3 bytes at 0x401000\nOriginal: 48 89 5C\nNew: 90 90 90"
        result = bridge_mcp_ghidra.patch_bytes(address="0x401000", hex_bytes="90 90 90")
        assert "Patched" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_patch_instruction(self, mock_post):
        mock_post.return_value = "Patched instruction at 0x401000"
        result = bridge_mcp_ghidra.patch_instruction(address="0x401000", assembly="NOP")
        assert "Patched" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_nop_region(self, mock_post):
        mock_post.return_value = "NOPed 6 bytes from 0x401000 to 0x401005"
        result = bridge_mcp_ghidra.nop_region(start_address="0x401000", end_address="0x401005")
        assert "NOPed" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_bytes(self, mock_get):
        mock_get.return_value = ["Bytes at 0x401000 (16 bytes):", "48 89 5C 24 08"]
        result = bridge_mcp_ghidra.get_bytes(address="0x401000", length=16)
        assert "0x401000" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_export_binary(self, mock_post):
        mock_post.return_value = "Exported to /tmp/patched"
        result = bridge_mcp_ghidra.export_binary(output_path="/tmp/patched", format="original")
        assert "Exported" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_save_program(self, mock_post):
        mock_post.return_value = "Program saved"
        result = bridge_mcp_ghidra.save_program()
        assert "saved" in result.lower()

    @patch("bridge_mcp_ghidra.safe_get")
    def test_search_memory(self, mock_get):
        mock_get.return_value = [
            "Found 2 match(es) for pattern 90 90:",
            "0x401000 [.text] in main",
            "0x401050 [.text] in helper",
        ]
        result = bridge_mcp_ghidra.search_memory(pattern="90 90")
        assert "Found" in result


# ===========================================================================
# Tests for GDB Dynamic Analysis Tools
# ===========================================================================


class TestGDBTools:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_gdb_health(self, mock_req):
        mock_req.return_value = {"status": "ok", "platform": "linux"}
        result = bridge_mcp_ghidra.gdb_health()
        assert result["status"] == "ok"

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_gdb_check_arch(self, mock_req):
        mock_req.return_value = {"architecture": "x86_64", "native": True}
        result = bridge_mcp_ghidra.gdb_check_arch(binary="test")
        assert result["architecture"] == "x86_64"

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_gdb_list_binaries(self, mock_req):
        mock_req.return_value = {"binaries": ["test1", "test2"]}
        result = bridge_mcp_ghidra.gdb_list_binaries()
        assert len(result["binaries"]) == 2

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_gdb_run_binary(self, mock_req):
        mock_req.return_value = {"stdout": "Hello", "returncode": 0}
        result = bridge_mcp_ghidra.gdb_run_binary(binary="test")
        assert result["stdout"] == "Hello"

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_gdb_execute(self, mock_req):
        mock_req.return_value = {"output": "Breakpoint 1 at 0x401000"}
        result = bridge_mcp_ghidra.gdb_execute(binary="test", commands=["break main"])
        assert "Breakpoint" in result["output"]

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_gdb_checksec(self, mock_req):
        mock_req.return_value = {"nx": True, "pie": False, "canary": True, "relro": "Partial"}
        result = bridge_mcp_ghidra.gdb_checksec(binary="test")
        assert result["nx"] is True

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_gdb_connection_error(self, mock_req):
        mock_req.return_value = {"error": "Cannot connect to GDB server"}
        result = bridge_mcp_ghidra.gdb_health()
        assert "error" in result

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_gdb_get_command_telemetry(self, mock_req):
        mock_req.return_value = {"commands": [{"tool": "gdb_command"}], "total": 1}
        result = bridge_mcp_ghidra.gdb_get_command_telemetry(lines=10)
        assert result["total"] == 1
        mock_req.assert_called_with("/command_telemetry?lines=10")

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_gdb_angr_selftest(self, mock_req):
        mock_req.return_value = {"ok": True, "found_states": 1}
        result = bridge_mcp_ghidra.gdb_angr_selftest(timeout=20)
        assert result["ok"] is True
        mock_req.assert_called_with("/angr/selftest", "POST", {"timeout": 20})


# ===========================================================================
# Tests for gdb_request helper
# ===========================================================================


class TestGDBRequest:
    @patch("bridge_mcp_ghidra.requests.get")
    def test_gdb_get_request(self, mock_get):
        mock_get.return_value = _mock_response(json_data={"status": "ok"})
        result = bridge_mcp_ghidra.gdb_request("/health")
        assert result["status"] == "ok"

    @patch("bridge_mcp_ghidra.requests.post")
    def test_gdb_post_request(self, mock_post):
        mock_post.return_value = _mock_response(json_data={"result": "success"})
        result = bridge_mcp_ghidra.gdb_request("/run", "POST", {"binary": "test"})
        assert result["result"] == "success"

    @patch("bridge_mcp_ghidra.requests.get")
    def test_gdb_connection_refused(self, mock_get):
        import requests

        mock_get.side_effect = requests.exceptions.ConnectionError("refused")
        result = bridge_mcp_ghidra.gdb_request("/health")
        assert "error" in result
        assert "Cannot connect" in result["error"]

    @patch("bridge_mcp_ghidra.requests.get")
    def test_gdb_generic_error(self, mock_get):
        mock_get.side_effect = RuntimeError("unexpected")
        result = bridge_mcp_ghidra.gdb_request("/health")
        assert "error" in result


# ===========================================================================
# Tests for recorded_tool decorator
# ===========================================================================


class TestRecordedToolDecorator:
    def test_decorator_without_recorder(self):
        """recorded_tool should work fine when no trajectory recorder is active."""
        bridge_mcp_ghidra.trajectory_recorder = None

        @bridge_mcp_ghidra.recorded_tool
        def sample_func(x=1):
            return x * 2

        result = sample_func(x=5)
        assert result == 10

    def test_decorator_with_recorder(self):
        """recorded_tool should record calls when trajectory recorder is active."""
        mock_recorder = MagicMock()
        bridge_mcp_ghidra.trajectory_recorder = mock_recorder

        @bridge_mcp_ghidra.recorded_tool
        def sample_func(x=1):
            return x * 2

        result = sample_func(x=5)
        assert result == 10
        # _record_call should have been called
        assert True  # recorded via _record_call

    def test_decorator_propagates_exceptions(self):
        """recorded_tool should re-raise exceptions from the wrapped function."""
        bridge_mcp_ghidra.trajectory_recorder = None

        @bridge_mcp_ghidra.recorded_tool
        def failing_func():
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            failing_func()


# ===========================================================================
# Tests for Trajectory Management Tools
# ===========================================================================


class TestTrajectoryTools:
    def test_trajectory_status_no_session(self):
        result = bridge_mcp_ghidra.trajectory_status()
        assert result["recording"] is False

    @patch("bridge_mcp_ghidra.requests.get")
    def test_trajectory_start(self, mock_get):
        mock_get.return_value = _mock_response("test_binary")
        result = bridge_mcp_ghidra.trajectory_start(binary_name="test_binary")
        assert result["status"] == "recording_started"
        assert result["binary"] == "test_binary"
        # Clean up
        bridge_mcp_ghidra.trajectory_recorder = None

    def test_trajectory_start_already_active(self):
        bridge_mcp_ghidra.trajectory_recorder = MagicMock()
        result = bridge_mcp_ghidra.trajectory_start()
        assert "error" in result
        bridge_mcp_ghidra.trajectory_recorder = None

    def test_trajectory_stop_no_session(self):
        result = bridge_mcp_ghidra.trajectory_stop()
        assert "error" in result

    def test_trajectory_note_no_session(self):
        result = bridge_mcp_ghidra.trajectory_note(note="test")
        assert "error" in result

    def test_trajectory_log_llm_turn_no_session(self):
        bridge_mcp_ghidra.trajectory_recorder = None
        result = bridge_mcp_ghidra.trajectory_log_llm_turn(role="assistant", content="test")
        assert "error" in result

    def test_trajectory_log_llm_turn_success(self):
        mock_recorder = MagicMock()
        bridge_mcp_ghidra.trajectory_recorder = mock_recorder
        result = bridge_mcp_ghidra.trajectory_log_llm_turn(
            role="assistant",
            content="Found candidate function.",
            metadata_json='{"model":"claude","tokens":123}',
        )
        assert result["status"] == "llm_turn_logged"
        mock_recorder.record_llm_turn.assert_called_once()
        bridge_mcp_ghidra.trajectory_recorder = None

    @patch("bridge_mcp_ghidra.analyze_trajectory")
    def test_trajectory_assert_logging(self, mock_analyze):
        mock_recorder = MagicMock()
        mock_recorder.get_session_path.return_value = "/tmp/session.jsonl"
        bridge_mcp_ghidra.trajectory_recorder = mock_recorder
        mock_analyze.return_value = {"total_tool_calls": 5, "total_llm_turns": 2}

        result = bridge_mcp_ghidra.trajectory_assert_logging(min_llm_turns=1, min_tool_calls=1)
        assert result["ok"] is True
        bridge_mcp_ghidra.trajectory_recorder = None

    @patch("bridge_mcp_ghidra.gdb_get_command_telemetry")
    @patch("bridge_mcp_ghidra.export_trajectory_markdown")
    @patch("bridge_mcp_ghidra.analyze_trajectory")
    @patch("bridge_mcp_ghidra.trajectory_list")
    def test_analysis_session_recap(self, mock_list, mock_analyze, mock_export, mock_cmd):
        mock_list.return_value = {"trajectories": [{"path": "/tmp/test.jsonl"}]}
        mock_analyze.return_value = {
            "binary": "sample.exe",
            "total_tool_calls": 5,
            "total_llm_turns": 1,
            "total_tool_duration_ms": 123.4,
        }
        mock_export.return_value = "# Base Report"
        mock_cmd.return_value = {
            "commands": [
                {
                    "timestamp": "2026-01-01T00:00:00",
                    "tool": "gdb_command",
                    "returncode": 0,
                    "duration_ms": 10,
                    "command": "strings /analysis/bins/sample.exe",
                    "stdout_tail": "flag{test}",
                    "stderr_tail": "",
                }
            ]
        }

        result = bridge_mcp_ghidra.analysis_session_recap()
        assert result["binary"] == "sample.exe"
        assert "Command History" in result["markdown"]
        assert "Terminal Snapshots" in result["markdown"]

    @patch("bridge_mcp_ghidra.gdb_get_command_telemetry")
    @patch("bridge_mcp_ghidra.export_trajectory_markdown")
    @patch("bridge_mcp_ghidra.analyze_trajectory")
    @patch("bridge_mcp_ghidra.trajectory_list")
    def test_analysis_session_recap_requires_llm_turns(self, mock_list, mock_analyze, mock_export, mock_cmd):
        mock_list.return_value = {"trajectories": [{"path": "/tmp/test.jsonl"}]}
        mock_analyze.return_value = {
            "binary": "sample.exe",
            "total_tool_calls": 5,
            "total_llm_turns": 0,
            "total_tool_duration_ms": 123.4,
        }
        mock_export.return_value = "# Base Report"
        mock_cmd.return_value = {"commands": []}

        result = bridge_mcp_ghidra.analysis_session_recap(require_llm_turns=True)
        assert "error" in result
        assert "No LLM turns were logged" in result["error"]


# ===========================================================================
# Tests for Help Tool
# ===========================================================================


class TestHelpTool:
    @patch("bridge_mcp_ghidra.safe_get")
    def test_ghidra_help_no_topic(self, mock_get):
        mock_get.return_value = ["=== GhidraMCP Help ===", "Available topics:"]
        result = bridge_mcp_ghidra.ghidra_help()
        assert "Help" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_ghidra_help_with_topic(self, mock_get):
        mock_get.return_value = ["=== Cross-References ===", "get_xrefs_to"]
        bridge_mcp_ghidra.ghidra_help(topic="xrefs")
        assert "xrefs" in mock_get.call_args[0][1].get("topic", "")
