# CLAUDE.md — Engineering Conventions

This file governs how work is done in this repository. It takes precedence over the
project brief whenever the two disagree on conventions (workflow, style, process).
The brief is the authority on scope, architecture, and the delivery plan.

## Non-negotiable invariants (read this before touching anything)

`f5audit` runs against a **production BIG-IP** with a **read-only account**. The
following are structural guarantees, not style preferences. A change that weakens any
of them is rejected regardless of what it enables.

1. **The client is GET-only.** `F5ReadOnlyClient` exposes exactly one public request
   method: `get()`. No `post`/`put`/`patch`/`delete`/`request` methods may be added.
   The single non-GET call in the entire codebase is the token login, hardcoded to the
   `LOGIN_PATH` constant and not redirectable to any other route.
2. **No execution endpoints.** `/mgmt/tm/util/*` (bash, remote commands) and any other
   action-executing endpoint must not appear in the source — not in code, not in a
   docstring, not in a comment.
3. **No logout.** Deleting the auth token would be a write. Tokens expire on their own.
4. **Credentials never touch disk, logs, or the CLI surface.** Password comes from
   `getpass` or `F5_PASS` only. Never a CLI argument (visible in process lists), never
   logged, never written to the raw cache. `--verbose` must not print passwords or full
   tokens.
5. **TLS verification is on by default.** `--insecure` is explicit and prints a warning.
6. **The management plane is treated as fragile.** Sequential requests only — no threads,
   no async, no connection pooling tricks. Pagination via `$top`/`$skip`, 30 s timeout,
   at most 2 retries with exponential backoff, `--delay` between requests, and no
   `expandSubcollections=true` over a full collection.
7. **The tool never suggests executable cleanup.** The `tmsh` strings in the report are
   informational text for a human's change request. No generated scripts, no
   copy-paste-and-run artifacts.

These invariants are enforced by structural tests in `tests/test_client.py`
(no write verbs, exactly one POST and it lives in `login()`, no forbidden endpoint
strings anywhere in the package). Those tests are not optional and must not be relaxed
to accommodate a new feature.

## The one SSH exception: the `ping` post-process

`f5audit ping` is an **opt-in post-processing** subcommand that annotates an existing
xlsx report with ping results gathered over SSH. It exists because some read-only
accounts can SSH to the BIG-IP but are denied iControl REST. Its boundaries are as
strict as the REST invariants above:

1. **It is never part of collection or analysis.** No collection/analysis code imports
   `f5audit/pingcheck.py`; the command only reads and annotates an already generated
   report. The REST client and every invariant above are untouched, and the structural
   tests still grep every package file, including the SSH module.
2. **It is structurally ping-only.** The two fixed command templates in `pingcheck.py`
   are the only command-building sites, the single interpolated value is an
   `ipaddress`-validated IPv4 literal, and a runtime guard refuses any command that is
   not a ping. Nothing user-controllable is ever executed and nothing on the device is
   created, modified, or deleted — ping is read-only ICMP.
3. **Only removal candidates are pinged.** IPs are sourced exclusively from the
   Orphan Nodes sheet — by construction the nodes whose verdict is not `IN USE` — so
   in-use nodes are never touched.
4. **paramiko is optional and lazy.** It is the `ssh` extra (`pip install
   'f5audit[ssh]'`), imported only inside `SSHCommandRunner.connect`. The test suite
   must keep passing without paramiko installed, and no test opens a socket (the ping
   engine takes an injectable command runner).
5. **Credentials follow invariant 4 unchanged**: `F5_PASS` or `getpass`, never a CLI
   argument.

## Correctness invariants for verdicts

The report drives a human deletion decision on a production device. A false `ORPHAN`
is the worst failure mode this tool has. Therefore:

- **Never issue `ORPHAN` when the evidence is incomplete.** Denied partitions, an
  unreadable `ltm/rule`, or any missing inventory endpoint degrades orphan verdicts to
  `MANUAL REVIEW` or `UNRELIABLE (incomplete inventory)`.
- **Nothing touched by dynamic pool selection can be `ORPHAN`.** The ceiling is
  `MANUAL REVIEW`, always.
- **A monitor-dead pool with an `IN USE` member node cannot be `OFFLINE`.** The pool,
  and any dead virtual server reaching it, is capped at `MANUAL REVIEW`: the server
  behind it is alive (in a live pool, or answering its node-level monitor), so the
  outage may be maintenance. Node verdicts are decided first and do not depend on it.
- **Nothing owned by an iApp can be `ORPHAN`, `OFFLINE` or `INACTIVE`.** Nodes, pools
  and virtual servers carrying `appService` (or living in a `<name>.app` folder) are
  capped at `MANUAL REVIEW`: tmsh cannot remove them, only the iApp can.
- **Traffic verdicts are only valid on the ACTIVE unit.** On standby, traffic analysis
  is skipped by default and marked `UNRELIABLE (standby)` under `--allow-standby`.
- **Every traffic-based verdict carries counter-reset context** in its notes.

When in doubt between two verdicts, emit the more conservative one and explain why in
the `Notes` column.

## Documentation maintenance

`README.md` must always describe the state of the project that actually exists. Any
change to the CLI surface, collected endpoints, verdict rules, the data model, the
report sheets, or dependencies updates `README.md` **in the same commit** as the code
change. A change that alters behavior without a documentation update is incomplete.

The README keeps the essentials: what the tool is, the safety design, installation,
the collect-once/analyze-offline workflow, the flag table, the verdict table, and the
operational warning about collecting on the active unit with meaningful uptime. Deep
design rationale belongs in module docstrings next to the code it explains, not in a
document that will drift.

## Git workflow

The repository lives at `netasservice/f5audit` on GitHub.

- One branch per change, named `feat/<short-description>` or `fix/<short-description>`.
- Every change lands via a pull request into `main`. Never commit directly to `main`.
- `main` is protected: no direct pushes, PRs require the CI checks to pass before merge.
- Keep PRs scoped to one issue. A PR that touches any invariant in the two sections
  above says so explicitly in its description, and explains why the invariant still
  holds.

## Releases

The package is published to PyPI as `f5audit` via the `release.yml` workflow, which
uses PyPI Trusted Publishing (OIDC) — there is no stored API token to leak or rotate.

To cut a release:

1. Bump `__version__` in `f5audit/__init__.py` (the single source of version truth;
   `pyproject.toml` reads it dynamically). Land the bump through a normal PR.
2. Create a GitHub release with tag `v<version>` (e.g. `v0.1.0`) on `main`.
3. The workflow runs the tests, verifies the tag matches `__version__`, builds the
   sdist and wheel, and publishes. A tag/version mismatch fails the build on purpose.

## English-only rule

All code, identifiers, comments, commit messages, PR descriptions, and documentation
are written in English, regardless of the language used to discuss the work. This
includes user-facing CLI output, report column headers, and verdict labels.

## Coding principles

> Writing good code is less about making a machine understand your intent and more about
> ensuring other developers can easily read and modify your work later.

Follow these principles in order of priority.

### Architecture (SOLID)

- **Single Responsibility** — each function/class has exactly one reason to change.
- **Open/Closed** — extend behavior without modifying existing code.
- **Dependency Inversion** — depend on abstractions, not concrete implementations.

This is why `f5audit` layers strictly inward and one-directionally:

```
client  →  collector  →  parsing  →  correlator  →  analyzer  →  report
                                                                   ↑
                                        cli orchestrates ──────────┘
```

Each layer knows only about the one before it. `parsing` and everything downstream
consume a `CollectionData` — a bag of raw JSON — and never a live client, which is what
makes `--from-raw` a first-class mode rather than a debugging hack, and what lets the
entire test suite run without a socket. `analyzer` consumes `ParsedData` +
`Correlation` and knows nothing about HTTP; `report` consumes verdicts and knows nothing
about F5 semantics.

Respect the extension points instead of editing across layers:

- A new monitor type is an entry in `MONITOR_TYPES`.
- A new endpoint is a `_collect_*` method plus a parser; nothing downstream changes shape.
- A new verdict is a constant in `Verdict`, a rule method in `Analyzer`, and a fill color
  in `VERDICT_FILLS`.
- A new output format is a writer function in `report.py` fed by the same `ReportTable`
  list — the tables are built once, format-agnostically.

### Simplicity triad

- **DRY** — extract repeated logic into reusable helpers.
- **KISS** — choose the simplest design; avoid clever or over-engineered solutions.
- **YAGNI** — do not write code for assumed future requirements.

**Dependency minimalism is part of KISS here.** This tool runs on a locked-down Windows
VDI where installing packages is friction. Runtime dependencies are `requests` and
`openpyxl`, full stop. Prefer `dataclasses` over pydantic, `argparse` over typer/click,
`csv` over pandas. Adding a third runtime dependency requires justifying why stdlib
cannot do the job.

### Daily practices

- Descriptive naming: clear, unambiguous identifiers — no single-letter variables.
- PEP 8 formatting throughout, enforced by `ruff check` and `ruff format --check` in CI.
  The ruff configuration lives in `pyproject.toml` and is the only one that counts —
  do not rely on user-global ruff settings.
- Comments explain *why*, not *what*. If removing a comment wouldn't confuse a future
  reader, don't write it. The comments that earn their place in this codebase are the
  ones recording a safety constraint or an F5 quirk (IPv6 member ports use `.`, monitor
  strings can read `min 1 of { ... }`, stats documents key by URL rather than name).
- Wrap external calls (HTTP, file I/O) in `try`/`except` and surface meaningful error
  strings — `F5ClientError` / `F5APIError` with the offending path. A raw traceback
  never reaches the end user; `--verbose` is what exposes it.
- Always clean up and persist in `finally` blocks. `Collector.collect()` writes its
  metadata in a `finally` precisely so an aborted collection still leaves a usable
  raw cache behind.
- Degrade, don't crash. A 403 on one endpoint records the gap and continues with
  weakened verdicts; a 404 on an unprovisioned monitor type is ignored silently. The
  only clean abort is a connection failure that survives retries, and even that keeps
  what was already collected.

## Testing

- **No test may touch the network.** Everything runs from anonymized JSON fixtures in
  `tests/fixtures/` and mocked `requests` sessions. A test that needs a live BIG-IP is
  not a test.
- Every PR keeps CI green: `ruff check`, `ruff format --check`, and `pytest` across
  Python 3.9–3.14 (`.github/workflows/ci.yml`). Run `pytest` and `ruff check` locally
  before pushing. New logic ships with tests in the same change.
- The highest-value, most test-critical code is the iRule Tcl analysis in `parsing.py`
  and the verdict rules in `analyzer.py`. Every verdict rule has both a positive and a
  negative case. Every new iRule pattern (static, implicit partition, `$variable`,
  `[command]`, datagroup lookup, commented out, nested braces) gets a case.
- Fixtures are anonymized by construction: RFC 5737 addresses (`192.0.2.x`), RFC 1918
  internals, `example.net` hostnames. Never commit a fixture derived from real customer
  configuration without scrubbing addresses, hostnames, and iRule business logic.

## Working against the real device

Development happens offline. The expected loop is: **one** `collect --save-raw` per
session against the live F5, then N iterations of `analyze --from-raw` against that
cache. Collection is resumable: `collect --save-raw` pointed at an existing raw
directory fetches only the datasets that have no file (resume an aborted run, top up
an old cache), which is also the cheap way to backfill newly collected endpoints
without a full re-collection. Do not point a dev loop at the production management interface — every iteration
is load on a plane that also carries HA heartbeats and admin access.

Before the first collection on a new device, run `f5audit validate` and read the
diagnosis table. It is cheap — a login plus eight probes — and it turns a
mid-collection failure into a five-second answer.
