# DNS Zone Resolution Simulator

A `nanoagent.plugin/v0001` plugin for the COMP 480/580 verifiable-tasks
milestone. It resolves ordered `A` and `AAAA` queries against a supplied
offline authoritative zone and reports deterministic answers and trace steps.

## Tools and task

| Tool | Does | Code |
|---|---|---|
| `read_zone` | Reads the zone origin, records, and ordered queries | `src/plugin/tools.py` |
| `write_resolutions` | Writes structured results to `resolutions.json` | `src/plugin/tools.py` |

| Task | Does | Runner |
|---|---|---|
| `simulate-dns-resolution` | Resolves direct records and CNAME chains or reports a precise failure outcome | `agent`, with `read_zone` and `write_resolutions` |

## Resolution rules

The input contains one lowercase absolute zone origin, authoritative `A`,
`AAAA`, and `CNAME` records, and one or more `A` or `AAAA` queries. Every name
must end in a dot and remain inside the supplied origin. Address text must use
the canonical representation produced by Python's `ipaddress` module.

For each query, resolution checks the requested address RRset first and then a
possible CNAME. CNAMEs are followed until an address RRset or terminal outcome
is reached. Address values are sorted by numeric IP value so input ordering
cannot change the expected result. The possible statuses are:

- `ANSWER`: the requested terminal RRset exists;
- `NXDOMAIN`: the final name has no records in the zone;
- `NODATA`: the final name exists but has neither the requested type nor a CNAME;
- `CNAME_LOOP`: traversal repeats a previously visited name.

An `ANSWER` includes its terminal address records. Each followed CNAME RRset
and the terminal address RRset are included as ordered trace steps. Failed
resolutions have no answers but retain any CNAME trace that led to the failure.

The input validator rejects malformed names, out-of-zone owners or targets,
invalid or non-canonical addresses, negative TTLs, duplicate records,
inconsistent RRset TTLs, multiple CNAMEs at one owner, and CNAME owners that
also contain another record type.

## Verification

The verifier independently builds RRsets and simulates every query. It requires
exactly one result per query in input order and compares the status, canonical
name, answers, and complete trace. It also checks that `write_resolutions`
actually writes the submitted report to `resolutions.json`.

Tests cover direct IPv4 and IPv6 answers, CNAME chains, numeric address
ordering, NXDOMAIN, NODATA, loops, malformed zone data, missing and extra
results, incorrect traces, and missing report files.

## Layout

```text
.
├── nanoagent.yaml
├── contract.py
├── README.md
├── LICENSE
├── pyproject.toml
├── uv.lock
├── .env
├── src/plugin/
├── tests/
├── ui/
├── product/
└── verifier/
```

The committed `.env` contains no secrets; it documents that this fully offline
plugin requires no environment variables.

## Develop and run

```bash
uv sync --extra dev
uv run ruff check .
uv run pytest -q
```

To publish, push the plugin to a public GitHub repository and submit its URL
through RUSH Lab.
