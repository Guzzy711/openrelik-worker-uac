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

import pytest

from src import uac
from tests.conftest import UAC_LOG


def test_catalog_has_the_uac_profiles():
    assert set(uac.PROFILES) == {"full", "ir_triage", "offline", "offline_ir_triage"}


@pytest.mark.parametrize("profile", sorted(uac.PROFILES))
def test_profiles_resolve_to_known_artifacts(profile):
    artifacts = uac.profile_artifacts(profile)
    assert artifacts
    assert set(artifacts) <= set(uac.ARTIFACTS)


def test_profile_excludes_are_applied():
    ir_triage = uac.profile_artifacts("ir_triage")
    assert "live_response/process/ps" in ir_triage
    assert "live_response/packages/package_owns_file" not in ir_triage
    assert not any(a.startswith("files/applications/ai_tools/") for a in ir_triage)


def test_offline_profiles_have_no_live_response():
    for profile in ("offline", "offline_ir_triage"):
        assert not any(a.startswith("live_response/") for a in uac.profile_artifacts(profile))


def test_resolve_artifacts_like_uac_option():
    assert uac.resolve_artifacts(["./artifacts/files/logs/var_log.yaml"]) == ["files/logs/var_log"]
    network = uac.resolve_artifacts(["live_response/network/*", "!live_response/network/ss.yaml"])
    assert "live_response/network/ip" in network
    assert "live_response/network/ss" not in network


def test_artifact_choices_include_categories_and_ids():
    choices = uac.artifact_choices()
    assert "live_response/network/*" in choices
    assert "files/logs/var_log" in choices


@pytest.mark.parametrize(
    "name,expected",
    [
        ("[root]/var/log/auth.log", "files/logs/var_log"),
        ("[root]/home/alice/.bash_history", "files/shell/bash"),
        ("[root]/root/.zsh_history", "files/shell/zsh"),
        ("[root]/etc/passwd", "files/system/etc"),
        ("live_response/network/ss_-anp.txt", "live_response/network/ss"),
        ("live_response/process/proc/12/status.txt", "live_response/process/procfs_information"),
        ("bodyfile/bodyfile.txt", "bodyfile/bodyfile"),
        ("hash_executables/hash_executables.sha1", "hash_executables/hash_executables"),
        ("system/suid.txt", "system/suid"),
        ("uac.log", None),
    ],
)
def test_classifier(name, expected):
    assert uac.Classifier().classify(name) == expected


def test_classifier_limited_to_selection():
    classifier = uac.Classifier(["live_response/network/ss"])
    assert classifier.classify("live_response/network/ss_-anp.txt") == "live_response/network/ss"
    assert classifier.classify("[root]/var/log/auth.log") is None


def test_original_path():
    assert uac.original_path("[root]/var/log/auth.log") == "/var/log/auth.log"
    assert uac.original_path("live_response/network/ss.txt") == "live_response/network/ss.txt"


def test_parse_log():
    info = uac.parse_log(UAC_LOG)
    assert info.uac_version == "3.4.0"
    assert info.hostname == "testhost"
    assert info.os == "linux"
    assert info.profile_name == "ir_triage"
    assert info.artifacts_selected == 3
    assert info.parsed_artifacts == [
        "live_response/network/ss",
        "files/logs/var_log",
        "files/shell/bash",
    ]
    assert info.artifacts() == info.parsed_artifacts
    assert info.skipped_conditions == 1
    assert len(info.errors) == 1
    assert (info.finished - info.started).total_seconds() == 62


def test_parse_log_artifacts_option_without_parsing_lines():
    info = uac.parse_log(
        "2026-11-26 06:48:58 +0100 INF Command line: ./uac -a"
        " live_response/network/ss.yaml,files/logs/* /tmp\n"
    )
    assert info.profile == ""
    assert "live_response/network/ss" in info.artifacts()
    assert "files/logs/var_log" in info.artifacts()


def test_parse_log_custom_profile_file():
    info = uac.parse_log(
        "2026-11-26 06:48:58 +0100 INF Command line: ./uac -p /cases/my_triage.yaml /tmp\n"
    )
    assert info.profile_name == "my_triage"


def test_iter_archive_tar_skips_traversal(uac_tar):
    members = {m.name: m for m, _ in uac.iter_archive(uac_tar)}
    assert "../evil.txt" not in members and "evil.txt" not in members
    link = members["[root]/var/log/auth.log.link"]
    assert link.kind == "hardlink"
    assert link.linkname == "[root]/var/log/auth.log"


def test_iter_archive_zip(uac_zip):
    names = [m.name for m, _ in uac.iter_archive(uac_zip)]
    assert "uac.log" in names and "[root]/etc/passwd" in names


def test_read_log(uac_tar, uac_zip):
    assert "Hostname: testhost" in uac.read_log(uac_tar)
    assert "Hostname: testhost" in uac.read_log(uac_zip)


def test_hostname_from_filename():
    assert uac.hostname_from_filename("uac-web-01-linux-20261126064858.tar.gz") == "web-01"
    assert uac.hostname_from_filename("other.tar.gz") == ""
