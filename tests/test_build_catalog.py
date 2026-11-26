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

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "build_catalog", Path(__file__).parent.parent / "tools" / "build_catalog.py"
)
build_catalog = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_catalog)

ARTIFACT_FILE = """\
version: 1.0
condition: ! command_exists "x"
output_directory: /live_response/process
artifacts:
  -
    description: A command.
    supported_os: [linux]
    collector: command
    command: ps -ef
    output_file: ps_-ef.txt
  -
    description: Per process output.
    collector: command
    foreach: ls /proc
    command: strings /proc/%line%/exe
    output_directory: /live_response/process/proc/%line%
    output_file: strings.txt
    compress_output_file: true
  -
    description: History.
    collector: file
    path: %user_home%/.bash_history %user_home%/Library/"Application Support"/x
  -
    description: Logs.
    collector: file
    path: /var/log
    name_pattern: ["*.log", "messages"]
  -
    description: Hooks.
    collector: file
    path: /
    path_pattern: ["*/.git/hooks/*"]
  -
    description: Built at collection time.
    collector: file
    path: %temp_directory%/list.txt
    is_file_list: true
"""


def test_parse_artifact_file_and_patterns():
    data = build_catalog.parse_artifact_file(ARTIFACT_FILE)
    assert data["output_directory"] == "/live_response/process"
    entries = data["artifacts"]
    assert len(entries) == 6
    assert entries[0]["supported_os"] == ["linux"]
    assert entries[1]["compress_output_file"] is True

    assert build_catalog.output_patterns(entries[0], data["output_directory"]) == [
        "live_response/process/ps_-ef.txt"
    ]
    assert build_catalog.output_patterns(entries[1], data["output_directory"]) == [
        "live_response/process/proc/*/strings.txt.gz"
    ]
    history = build_catalog.file_patterns(entries[2])
    assert "*/.bash_history" in history
    assert "*/Library/Application Support/x" in history
    logs = build_catalog.file_patterns(entries[3])
    assert "/var/log/*/*.log" in logs and "/var/log/messages" in logs
    assert build_catalog.file_patterns(entries[4]) == ["/*/.git/hooks/*"]
    assert build_catalog.file_patterns(entries[5]) == []


def test_parse_profile_keeps_excludes():
    profile = build_catalog.parse_profile(
        "name: p\ndescription: A profile.\nartifacts:\n  - files/*\n  - !files/x.yaml # no\n"
    )
    assert profile == {
        "name": "p",
        "description": "A profile.",
        "artifacts": ["files/*", "!files/x.yaml"],
    }
