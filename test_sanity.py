import pytest
from flow_sast_mcp.server import create_server
from flow_sast_mcp.tools import fp_filter
import json
import os
from pathlib import Path

def test_server_creation():
    server = create_server()
    assert server is not None
    assert server.name == "flow-sast"

def test_fp_filter_basic(tmp_path_factory):
    # This isn't using tmp_path correctly yet because ensure_run_dirs creates in cwd,
    # but we can try to run it.
    paths = [
        {
            "entry_file": "/app/tests/LoginTest.php",
            "score": 8,
            "sink": {"name": "DB::statement"}
        },
        {
            "entry_file": "/app/controller/LoginController.php",
            "score": 9,
            "sink": {"name": "DB::statement"}
        }
    ]
    result = fp_filter.run("test_run_123", paths)
    assert result["removed_count"] == 1
    assert result["pass_count"] == 1
    assert "test_run_123" in result["saved_to"]

@pytest.mark.asyncio
async def test_list_tools():
    server = create_server()
    pass
