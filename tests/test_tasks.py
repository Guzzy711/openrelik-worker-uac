# Copyright 2026 Guzzy
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src import tasks
from tests.conftest import input_file


@pytest.fixture(autouse=True)
def no_telemetry():
    with patch("src.tasks.telemetry"):
        yield


def run(task, path, output_path, config=None):
    self = MagicMock()
    result = task.__class__.run(
        self,
        input_files=[input_file(path)],
        output_path=str(output_path),
        workflow_id="wf",
        task_config=config or {},
    )
    return json.loads(base64.b64decode(result))


def by_original_path(result):
    return {f["original_path"]: f for f in result["output_files"]}


def test_report(uac_tar, tmp_path):
    result = run(tasks.report, uac_tar, tmp_path)
    assert result["task_report"]["summary"].startswith(
        "testhost (linux), UAC 3.4.0, profile ir_triage:"
    )
    content = Path(result["output_files"][0]["path"]).read_text()
    assert "`files/logs/var_log`" in content
    assert "`live_response/network/ss`" in content
    assert "_find_based_collector" in content


def test_extract_artifacts(uac_tar, tmp_path):
    result = run(
        tasks.extract,
        uac_tar,
        tmp_path,
        {"artifacts": ["files/logs/var_log", "live_response/network/*"]},
    )
    files = by_original_path(result)
    assert set(files) == {
        "/var/log/auth.log",
        "/var/log/auth.log.link",
        "live_response/network/ss_-anp.txt",
    }
    auth = files["/var/log/auth.log"]
    assert auth["data_type"] == "uac:artifact:files/logs/var_log"
    assert auth["display_name"] == "auth.log"
    assert Path(auth["path"]).read_text().startswith("Nov 26")
    # The hard link gets the content of its target.
    assert Path(files["/var/log/auth.log.link"]["path"]).read_text() == Path(auth["path"]).read_text()


def test_extract_file_filter(uac_zip, tmp_path):
    result = run(tasks.extract, uac_zip, tmp_path, {"file_filter": "/etc/passwd, uac.log"})
    files = by_original_path(result)
    assert set(files) == {"/etc/passwd", "uac.log"}
    assert files["/etc/passwd"]["data_type"] == "uac:file"


def test_extract_profile_auto_uses_artifacts_that_ran(uac_tar, tmp_path):
    result = run(tasks.extract, uac_tar, tmp_path, {"profile": tasks.PROFILE_AUTO})
    assert "/home/alice/.bash_history" in by_original_path(result)
    assert "bodyfile/bodyfile.txt" not in by_original_path(result)


def test_extract_profile(uac_tar, tmp_path):
    result = run(tasks.extract, uac_tar, tmp_path, {"profile": "offline"})
    files = by_original_path(result)
    assert "bodyfile/bodyfile.txt" in files
    assert "live_response/network/ss_-anp.txt" not in files


def test_extract_needs_a_selection(uac_tar, tmp_path):
    with pytest.raises(RuntimeError, match="Select artifacts"):
        run(tasks.extract, uac_tar, tmp_path, {})


def test_extract_no_match(uac_tar, tmp_path):
    with pytest.raises(RuntimeError, match="No files"):
        run(tasks.extract, uac_tar, tmp_path, {"file_filter": "/nothing"})


def test_no_uac_input(tmp_path):
    with pytest.raises(RuntimeError, match="No UAC archive"):
        run(tasks.report, str(tmp_path / "notes.txt"), tmp_path)


def test_chained_after_another_task_explains_input(tmp_path):
    # Chained after the report, the input is the report's .md, not the archive.
    with pytest.raises(RuntimeError, match="directly to the UAC archive"):
        run(tasks.extract, str(tmp_path / "uac_report.md"), tmp_path, {"profile": "offline"})


def test_timeline_timesketch(uac_tar, tmp_path):
    result = run(tasks.timeline_task, uac_tar, tmp_path)
    files = {f["display_name"]: f for f in result["output_files"]}
    base = "uac-testhost-linux-20261126064858"
    assert set(files) == {
        f"{base}_{source}.jsonl"
        for source in ("uac_log", "bodyfile", "live_response", "hash_executables", "shell_history")
    }
    for output in files.values():
        for line in Path(output["path"]).read_text().splitlines():
            record = json.loads(line)
            assert {"message", "datetime", "timestamp_desc"} <= set(record)
            assert record["hostname"] == "testhost"
    history = Path(files[f"{base}_shell_history.jsonl"]["path"]).read_text()
    assert "curl http://x" in history


def test_timeline_elasticsearch_sources(uac_tar, tmp_path):
    result = run(
        tasks.timeline_task,
        uac_tar,
        tmp_path,
        {"sources": ["bodyfile"], "output_format": "Elasticsearch bulk NDJSON"},
    )
    [output] = result["output_files"]
    assert output["display_name"].endswith("_bodyfile_part001.ndjson")
    lines = Path(output["path"]).read_text().splitlines()
    assert json.loads(lines[0]) == {"index": {"_index": "uac-testhost"}}
    assert json.loads(lines[1])["event"]["module"] == "uac"


def test_timeline_unknown_source(uac_tar, tmp_path):
    with pytest.raises(RuntimeError, match="Unknown sources"):
        run(tasks.timeline_task, uac_tar, tmp_path, {"sources": ["nope"]})
