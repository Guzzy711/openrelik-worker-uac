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

import io
import tarfile
import zipfile

import pytest

UAC_LOG = """\
2026-11-26 06:48:58 +0100 INF Unix-like Artifacts Collector 3.4.0
2026-11-26 06:48:58 +0100 INF Command line: ./uac --profile ir_triage /tmp/out
2026-11-26 06:48:58 +0100 INF Operating system: linux
2026-11-26 06:48:58 +0100 INF System architecture: x86_64
2026-11-26 06:48:58 +0100 INF Hostname: testhost
2026-11-26 06:48:58 +0100 INF Time zone: Europe/Copenhagen
2026-11-26 06:48:58 +0100 INF Mount point: /
2026-11-26 06:48:59 +0100 INF 3 artifact(s) selected
2026-11-26 06:49:00 +0100 INF Parsing live_response/network/ss.yaml
2026-11-26 06:49:00 +0100 CMD ss -anp
2026-11-26 06:49:01 +0100 INF Parsing files/logs/var_log.yaml
2026-11-26 06:49:02 +0100 INF Parsing files/shell/bash.yaml
2026-11-26 06:49:02 +0100 INF Global condition 'command_exists "x"' not satisfied. Skipping...
2026-11-26 06:49:03 +0100 ERR _find_based_collector: No such file or directory
2026-11-26 06:50:00 +0100 INF Artifacts collection completed in 62 seconds
"""

BODYFILE = (
    "0|/etc/passwd|10|-rw-r--r--|0|0|100|1700000000|1600000000|1600000000|0\n"
    "0|/tmp/a|b|11|-rw-r--r--|1000|1000|5|1700000100|1700000200|1700000300|1700000400\n"
)

BASH_HISTORY = "#1700000000\nwhoami\nls -la\n#1700000060\ncurl http://x\n"

MEMBERS = {
    "uac.log": UAC_LOG,
    "bodyfile/bodyfile.txt": BODYFILE,
    "live_response/network/ss_-anp.txt": "Netid State\ntcp LISTEN 0.0.0.0:22\n",
    "live_response/process/proc/1/recovered_file": "\x7fELF binary",
    "hash_executables/hash_executables.md5": "d41d8cd98f00b204e9800998ecf8427e  /usr/bin/ls\n",
    "[root]/var/log/auth.log": "Nov 26 06:00:00 testhost sshd[1]: Accepted\n",
    "[root]/home/alice/.bash_history": BASH_HISTORY,
    "[root]/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
}


def _add(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = 1795672140
    archive.addfile(info, io.BytesIO(data))


@pytest.fixture
def uac_tar(tmp_path):
    """A small UAC tar.gz, with a hard link and a path traversal member."""
    path = tmp_path / "uac-testhost-linux-20261126064858.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, text in MEMBERS.items():
            _add(archive, name, text.encode())
        link = tarfile.TarInfo("[root]/var/log/auth.log.link")
        link.type = tarfile.LNKTYPE
        link.linkname = "[root]/var/log/auth.log"
        archive.addfile(link)
        _add(archive, "../evil.txt", b"evil")
    return str(path)


@pytest.fixture
def uac_zip(tmp_path):
    path = tmp_path / "uac-testhost-linux-20261126064858.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in MEMBERS.items():
            archive.writestr(name, text)
    return str(path)


def input_file(path: str) -> dict:
    return {"id": 7, "path": path, "display_name": path.rsplit("/", 1)[-1]}
