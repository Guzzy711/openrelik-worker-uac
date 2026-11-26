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

import json
from datetime import datetime, timezone

import pytest

from src import timeline
from tests.conftest import BASH_HISTORY, BODYFILE


@pytest.mark.parametrize(
    "name,expected",
    [
        ("uac.log", "uac_log"),
        ("bodyfile/bodyfile.txt", "bodyfile"),
        ("hash_executables/hash_executables.md5", "hash_executables"),
        ("live_response/network/ss_-anp.txt", "live_response"),
        ("live_response/process/proc/1/recovered_file", None),
        ("live_response/process/proc/1/strings.txt.gz", None),
        ("system/suid.txt", "system"),
        ("[root]/home/alice/.bash_history", "shell_history"),
        ("[root]/root/.local/share/fish/fish_history", "shell_history"),
        ("[root]/var/log/auth.log", None),
    ],
)
def test_source_of(name, expected):
    assert timeline.source_of(name) == expected


def test_bodyfile_groups_equal_timestamps():
    events = list(timeline.parse_bodyfile(BODYFILE.splitlines()))
    passwd = [e for e in events if e.fields["path"] == "/etc/passwd"]
    # mtime == ctime, atime differs, crtime 0 is skipped.
    assert sorted(e.fields["macb"] for e in passwd) == [".a..", "m.c."]
    mc = next(e for e in passwd if e.fields["macb"] == "m.c.")
    assert mc.timestamp_desc == "Content Modification Time; Metadata Modification Time"
    assert mc.datetime == datetime.fromtimestamp(1600000000, tz=timezone.utc)
    # A "|" in the name is kept.
    assert {e.fields["path"] for e in events} == {"/etc/passwd", "/tmp/a|b"}
    assert len([e for e in events if e.fields["path"] == "/tmp/a|b"]) == 4


def test_shell_history_bash():
    events = list(timeline.parse_shell_history("/home/alice/.bash_history", BASH_HISTORY.splitlines()))
    # "ls -la" has no timestamp of its own.
    assert [e.message for e in events] == ["whoami", "curl http://x"]
    assert events[1].datetime == datetime.fromtimestamp(1700000060, tz=timezone.utc)


def test_shell_history_zsh_and_fish():
    zsh = list(timeline.parse_shell_history("z", [": 1700000000:0;id", "plain"]))
    assert [e.message for e in zsh] == ["id"]
    fish = list(timeline.parse_shell_history("f", ["- cmd: uname -a", "  when: 1700000000"]))
    assert [e.message for e in fish] == ["uname -a"]


def test_uac_log_times_are_utc():
    events = list(
        timeline.parse_uac_log(["2026-11-26 06:48:58 +0100 INF Hostname: x", "garbage"])
    )
    assert len(events) == 1
    assert events[0].datetime.isoformat() == "2026-11-26T05:48:58+00:00"


def test_output_lines_parse_hashes_and_nul_separated_lines():
    collected = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = list(
        timeline.parse_output_lines(
            "hash_executables/hash_executables.md5",
            "hash_executables/hash_executables",
            collected,
            ["D41D8CD98F00B204E9800998ECF8427E  /usr/bin/ls", ""],
        )
    )
    assert len(events) == 1
    assert events[0].fields["hash"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert events[0].fields["algorithm"] == "md5"
    environ = list(
        timeline.parse_output_lines("live_response/x/environ.txt", None, collected, ["A=1\x00B=2"])
    )
    assert [e.message for e in environ] == ["A=1", "B=2"]


def _event():
    return timeline.Event(
        datetime=datetime(2026, 1, 1, tzinfo=timezone.utc),
        timestamp_desc="Log Time",
        message="hello",
        data_type="uac:test",
        fields={"path": "/x", "empty": None},
    )


def test_timesketch_record_has_required_fields():
    record = timeline.timesketch_record(_event(), "host")
    assert record["message"] == "hello"
    assert record["datetime"] == "2026-01-01T00:00:00+00:00"
    assert record["timestamp_desc"] == "Log Time"
    assert record["timestamp"] == 1767225600000000
    assert record["path"] == "/x"
    assert "empty" not in record


def test_writer_elasticsearch_bulk_rotates(tmp_path):
    paths = []

    def new_file(part):
        paths.append(tmp_path / f"part{part}.ndjson")
        return paths[-1]

    writer = timeline.Writer(
        timeline.FORMAT_ELASTICSEARCH, "host", "uac-host", new_file, max_bytes=400
    )
    for _ in range(5):
        writer.write(_event())
    writer.close()
    assert writer.events == 5
    assert len(paths) > 1
    lines = [json.loads(line) for p in paths for line in p.read_text().splitlines()]
    assert len(lines) == 10
    assert lines[0] == {"index": {"_index": "uac-host"}}
    assert lines[1]["@timestamp"] == "2026-01-01T00:00:00+00:00"
    assert lines[1]["host"]["name"] == "host"
    assert lines[1]["file"]["path"] == "/x"


def test_writer_timesketch_single_file(tmp_path):
    paths = []
    writer = timeline.Writer(
        timeline.FORMAT_TIMESKETCH, "host", "i", lambda part: paths.append(tmp_path / "t.jsonl") or paths[-1], max_bytes=10
    )
    for _ in range(3):
        writer.write(_event())
    writer.close()
    assert len(paths) == 1
    assert len(paths[0].read_text().splitlines()) == 3


def test_index_name():
    assert timeline.index_name("Web_01.Example") == "uac-web_01.example"
    assert timeline.index_name("") == "uac-unknown"
