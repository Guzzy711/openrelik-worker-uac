# OpenRelik worker: UAC

Processes collections made by [UAC (Unix-like Artifacts Collector)](https://github.com/tclahr/uac):
the `uac-<hostname>-<os>-<timestamp>.tar.gz` (or `.tar`, `.zip`) archive UAC writes.
It knows the artifacts and profiles of UAC 3.4.0 (`full`, `ir_triage`, `offline`,
`offline_ir_triage`) and collections made with `-a` or a custom profile file.

## Tasks

### UAC: Collection report

A markdown report of the collection, read from `uac.log` and the archive contents: host,
OS, UAC version, command line and profile, start and end time, the files per directory,
the files per UAC artifact, the artifacts that ran without output, and collection errors.

### UAC: Extract artifacts

Extracts the files of selected UAC artifacts, each as its own file that other workers
(Plaso, grep, strings, ...) can take as input.

- **Artifacts**: artifact names as in `uac -a`, such as `files/logs/var_log`,
  `files/shell/bash`, or a whole category, such as `live_response/network/*`.
- **Profile**: every artifact of a UAC profile. `auto (as collected)` takes the
  artifacts the collection ran (from the `Parsing ...` lines of `uac.log`); a named
  profile narrows a bigger collection, such as an `ir_triage` subset of a `full` one.
- **File filter**: comma separated globs on the original path (`/var/log/auth.log*`)
  or the path in the archive (`live_response/process/*`).

Files collected from the file system (`[root]/...` in the archive) keep their original
path (`/var/log/auth.log`); command output keeps its archive path
(`live_response/network/ss_-anp.txt`). The data type is `uac:artifact:<artifact>`, or
`uac:file` for files matched by the file filter only.

### UAC: Timeline (Timesketch / Elasticsearch)

Turns a collection into events, one output file per source:

| Source | Events |
| --- | --- |
| `bodyfile` | file system times from `bodyfile/bodyfile.txt`; times that are equal are one event with its MACB letters |
| `shell_history` | bash (`#<epoch>` lines), zsh extended history and fish entries that have a timestamp |
| `uac_log` | the lines of `uac.log` |
| `live_response` | every line of the live response command output (`.txt`), at the time UAC wrote the file |
| `system` | every line of the `system/` listings (suid, sgid, hidden and world writable files, ...) |
| `hash_executables` | the hash and path of every executable file |

Output formats:

- **Timesketch JSONL** (`.jsonl`): `message`, `datetime`, `timestamp`, `timestamp_desc`,
  `data_type`, `hostname`, and the fields of the source. Chain the task into the
  Timesketch worker, or import the files with the Timesketch importer.
- **Elasticsearch bulk NDJSON** (`_partNNN.ndjson`): an `index` action for index
  `uac-<hostname>` and an ECS-style document (`@timestamp`, `message`, `event.action`,
  `event.dataset`, `host.name`, `file.path`, and the fields of the source under `uac`).
  Files are split at 50 MB so each fits in one request:

  ```bash
  for f in *.ndjson; do
    curl -s -H 'Content-Type: application/x-ndjson' --data-binary @"$f" http://localhost:9200/_bulk
  done
  ```

Logs and other files in `[root]` are better parsed by Plaso: extract them with
*UAC: Extract artifacts* and chain Plaso.

## The artifact catalog

`src/catalog.json` says, for every UAC artifact file, where its output lands in the
archive, and lists the profiles. It's generated from a UAC release:

```bash
curl -sL https://github.com/tclahr/uac/releases/download/v3.4.0/uac-3.4.0.tar.gz | tar xz
python3 tools/build_catalog.py uac-3.4.0
```

A file is attributed to the artifact with the most specific matching path pattern.
Files UAC collected from a list built at collection time (`is_file_list`, such as
`$HISTFILE`) are attributed by the artifact's other patterns or not at all; the file
filter still reaches them.

## Deploy

Add the worker to the OpenRelik `docker-compose.yml`:

```yaml
  openrelik-worker-uac:
    container_name: openrelik-worker-uac
    image: ghcr.io/guzzy711/openrelik-worker-uac:latest
    restart: always
    environment:
      - REDIS_URL=redis://openrelik-redis:6379
    volumes:
      - ./data:/usr/share/openrelik/data
    command: "celery --app=src.app worker --task-events --concurrency=2 --loglevel=INFO -Q openrelik-worker-uac"
```

Then `docker compose up -d openrelik-worker-uac`. To build the image yourself:
`docker build -t openrelik-worker-uac .`

## Test

```bash
uv sync --group test
uv run pytest -s --cov=.
```

## License

Apache 2.0, see [LICENSE](LICENSE).
