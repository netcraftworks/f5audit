# f5audit

[![CI](https://github.com/netasservice/f5audit/actions/workflows/ci.yml/badge.svg)](https://github.com/netasservice/f5audit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/f5audit?label=pypi)](https://pypi.org/project/f5audit/)
[![Python](https://img.shields.io/pypi/pyversions/f5audit?label=python)](https://pypi.org/project/f5audit/)

Read-only audit tool for **F5 BIG-IP LTM**. It collects configuration and
statistics via iControl REST (GET only), correlates object references, and
produces a multi-sheet **Excel report** identifying unused objects (nodes,
pools, virtual servers, monitors) as input for a human-driven, change-
controlled cleanup.

**This tool never modifies the device.** The "suggested command" columns in
the report are informational text only; nothing is ever executed.

## Safety design

- The HTTP client (`F5ReadOnlyClient`) exposes a single `get()` method.
  There are no `post`/`patch`/`put`/`delete` methods. The only internal
  write is the token login, hardcoded to `/mgmt/shared/authn/login`.
  This is enforced by structural tests.
- No `tmsh`/bash execution endpoints are used or referenced anywhere.
- No explicit logout (deleting the token would be a write); tokens expire
  on their own (~20 minutes).
- Passwords are read from an interactive prompt (`getpass`) or the
  `F5_PASS` environment variable — never from a CLI argument, and never
  written to disk or logs.
- Management-plane friendly: sequential requests only, `$top`/`$skip`
  pagination, per-request delay (`--delay`, default 0.1 s), 30 s timeout,
  max 2 retries with exponential backoff.
- The optional `ping` post-process is the sole SSH feature: opt-in,
  separate from collection, and structurally ping-only — fixed command
  templates, the only interpolated value is an `ipaddress`-validated
  IPv4 literal, and non-ping commands are refused at runtime. Ping is
  read-only ICMP; nothing on the device is created, modified, or
  deleted. SSH host keys are auto-accepted (management-network tool,
  same spirit as `--insecure`).

## Requirements

- Python >= 3.9, `requests`, `openpyxl`
- An account with a **read-only role** (Auditor/Guest) and iControl REST
  access on the BIG-IP
- Network access to the management interface (TCP 443)
- Only for the optional `ping` post-process: `pip install 'f5audit[ssh]'`
  (paramiko) and SSH access (TCP 22) with an account that can run `ping`

## Installation

```
pip install f5audit
```

From source: `pip install .` — or without installing, from the project
directory: `python -m f5audit ...`

## Usage

### 1. Validate access first

```
f5audit validate --host 192.0.2.1 --user auditor --insecure
```

Probes login plus the key GET endpoints and prints a diagnosis per
response code (bad credentials, missing REST access, denied endpoints,
old BIG-IP versions, network timeouts).

### 2. Collect once, analyze offline N times

```
f5audit collect --host 192.0.2.1 --user auditor --insecure --save-raw ./raw/
f5audit analyze --from-raw ./raw/ --out report.xlsx
```

`collect` saves every raw JSON response (with timestamps) to disk;
`analyze --from-raw` re-analyzes from that cache **without touching the
F5 again**. This is the recommended workflow: one collection per session,
all further analysis offline.

**Resumable collection**: pointing `--save-raw` at a directory that
already contains raw JSON fetches **only the missing datasets** — use it
to resume an aborted collection, or to top up an old cache with data a
newer version collects (e.g. the ARP/self-IP tables). Whatever failed
previously has no file and is retried once; whatever succeeded is never
re-fetched. Note the resulting cache mixes collection times (flagged on
the Summary sheet); for a fully time-consistent snapshot, use a fresh
directory.

### One-step alternative

```
f5audit analyze --host 192.0.2.1 --user auditor --insecure --save-raw ./raw/ --out report.xlsx
```

### 3. Optional post-process: ping the removal candidates over SSH

```
pip install 'f5audit[ssh]'
f5audit ping --report report.xlsx --host 192.0.2.1 --user auditor
```

Double-checks the removal candidates in an **already generated** report:
a node with no ARP entry that also does not answer ping is a much safer
deletion conversation. The command reads the `IP` column of the
**Orphan Nodes** sheet — by construction the nodes that are *not*
`IN USE`, so in-use nodes are never pinged — deduplicates the IPs (a
node in several pools is pinged once), runs `ping` on the BIG-IP over
SSH for each unique IPv4, and writes two columns into both the
Inventory and Orphan Nodes sheets **in place**, replicating each IP's
result across every row where it appears (on Inventory it fills the
`Ping (from F5)` / `Ping note` columns the report already reserves, so
the other columns never move):

| `Ping (from F5)` | Meaning |
|---|---|
| `YES` / `NO` | The node answered / did not answer ICMP from the F5 |
| `UNKNOWN` | Ping output could not be parsed (raw excerpt in `Ping note`) |
| `NOT TESTED` | Skipped: non-zero route domain, IPv6, FQDN node, or SSH failed mid-run |

Notes:

- Works with both Advanced-shell (bash) and tmsh-shell accounts — the
  command form is auto-detected with one probe.
- Password from `F5_PASS` or an interactive prompt, as everywhere else;
  SSH keys/agent are also tried automatically.
- Close the report in Excel first: if the file is locked, results are
  saved to `<name>_ping.xlsx` instead of being lost.
- Re-running overwrites the ping columns (never duplicates them).
- Like ARP, ping is point-in-time evidence: `NO` means "did not answer
  at that moment", not "gone". `--count` (default 2) echo requests are
  sent per IP, sequentially.

### Options

| Flag | Meaning |
|---|---|
| `--user` / `F5_USER` | Username (password via prompt or `F5_PASS`) |
| `--login-provider` | Token auth provider (default `tmos`; set for TACACS+/RADIUS) |
| `--insecure` | Skip TLS verification (self-signed mgmt certs); prints a warning |
| `--delay` | Seconds between requests (default 0.1) |
| `--top` | Pagination page size (default 100) |
| `--format xlsx\|csv` | Excel workbook or one CSV per sheet |
| `--allow-standby` | On a standby unit, emit traffic- and availability-based verdicts marked `UNRELIABLE (standby)` instead of skipping them |
| `--report` (`ping`) | Existing .xlsx report to annotate in place |
| `--ssh-port` (`ping`) | SSH port (default 22) |
| `--count` (`ping`) | Echo requests per IP (default 2) |

Exit codes: `0` OK · `1` connection/auth error · `2` analysis completed
with warnings (standby device, denied partitions, missing endpoints).

## Verdicts

| Verdict | Meaning |
|---|---|
| `ORPHAN` | Not referenced by anything (node: no pool membership; pool: no VS/iRule/policy reference; monitor: no user). Only issued when the inventory is complete and no attached dynamic iRule can reach the object (see `MANUAL REVIEW`). |
| `MANUAL REVIEW` | A dynamic iRule (`pool $var`, `pool [...]` — including datagroup lookups whose value reaches the `pool` command; a `class match` used only as a condition before `pool <literal>` is a static reference) or a missing `ltm/rule` endpoint means the object *could* be referenced at runtime. Never auto-cleanup these. A dynamic iRule attached to a virtual server reaches the pools of its own partition, the VS's partition, `/Common`, and any partition named literally (`/Partition/...`) in its Tcl; pools in other partitions are not affected, and nodes inherit the reach of their pools. Objects owned by an **iApp** are also capped here: a node, pool or virtual server that would otherwise be `ORPHAN`, `OFFLINE` or `INACTIVE` becomes `MANUAL REVIEW`, with the iApp name and the original evidence in the notes. Ownership is read from the `appService` attribute BIG-IP sets on iApp objects (for nodes, also through their pool membership), with the `<name>.app` folder as a fallback. With strict updates tmsh refuses to modify these objects, and without it the next iApp reconfigure recreates them, so removal has to go through the iApp. |
| `INACTIVE` | Configured and referenced, but disabled or zero total connections since the last counter reset. |
| `OFFLINE (decommission candidate)` | Referenced, but the whole dependency chain is monitor-offline: every member of the pool is down, so the pool and its virtual servers are offline. A deletion candidate to confirm with the config owner — availability is point-in-time, so it may also mean maintenance. A node is only included when it is dead in **every** pool it belongs to; a node alive in another pool stays `IN USE` ("in use elsewhere"). Only issued on the ACTIVE unit. A pool is capped at `MANUAL REVIEW` when an attached dynamic iRule can reach it (deleting the pool could break that iRule at runtime); its dead member nodes are not — dynamic iRules select pools, never nodes, and do not change pool membership. |
| `UNRELIABLE (standby)` | Traffic-based verdict computed on a standby unit (only with `--allow-standby`). |
| `UNRELIABLE (incomplete inventory)` | Some partitions were not readable; a reference could exist in an invisible partition. |
| `IN USE` | Everything else. |

## Operational warning

- **Collect on the ACTIVE unit** of the HA pair. On a standby unit traffic
  counters are zeros and the tool will skip traffic analysis (or mark it
  `UNRELIABLE` with `--allow-standby`).
- Traffic counters reset on reboot / stats reset. Ideally collect after
  **several weeks of uptime**; the report includes the failover-state age
  as context.
- `INACTIVE` means "no traffic since the counters started", not "safe to
  delete". Use the planned `compare` workflow (v2) — two collections some
  weeks apart — to distinguish real zero traffic from a recent reset.
  The raw cache already stores per-file timestamps to enable this.
- Availability is **point-in-time**: an `OFFLINE` chain reflects monitor
  state at collection time and may mean maintenance rather than
  decommissioning. Always confirm with the config owner before requesting
  deletion.
- The ARP table is also point-in-time and **per-unit**: "no ARP entry"
  on a local subnet means the host was idle (or down) at collection time
  — dynamic entries expire after minutes of silence — and on a standby
  unit the table reflects that unit, not the pair. The network columns
  are informational context, never a verdict input.

## Report sheets

1. **Summary** — hostname, version, HA state, uptime context, partitions,
   verdict counts, active warnings.
2. **Inventory** — one row per pool member (plus rows for pool-less
   nodes), fully correlated: node ↔ pool ↔ virtual server ↔ monitor ↔
   iRule/policy references, statuses and traffic, plus the network
   context columns described below. Each row carries both
   the `Node verdict` and the (colored) `Pool verdict` with its notes,
   since a node can be `OFFLINE` inside a pool held at `MANUAL REVIEW`.
   Two columns
   concern iRules and are not expected to match: `VS iRules` is
   configuration (the iRules attached to the row's virtual servers — in
   F5, iRules only attach to virtual servers), while `iRules selecting
   pool` is code analysis (every iRule whose Tcl contains `pool <this
   pool>`, whichever virtual server it is attached to). The latter, with
   `Policies forwarding to pool`, is the evidence that keeps a pool with no
   default-pool reference from being `ORPHAN`. Columns `V:W` are reserved
   for `f5audit ping`, and `X:AA` hold the change-request commands
   described below.
3. **Orphan Nodes** · 4. **Orphan-Inactive Pools** (with the same
   `iRules selecting pool` / `Policies forwarding to pool` evidence
   columns) · 5. **Inactive Virtual Servers** (with the attached
   `iRules`) — filtered views with informational `tmsh` commands for the
   change request.
6. **Dead Chains** — one row per monitor-offline pool (verdict
   `OFFLINE (decommission candidate)`, or `MANUAL REVIEW` when dynamic
   iRules cap it), grouping the whole chain (virtual servers → pool →
   member nodes) with per-object verdicts and the informational
   `tmsh delete` lines to take to the config owner. Only objects with an
   `OFFLINE` verdict get a delete line: a capped pool, or a node still
   alive in another pool, is listed without one.
7. **Orphan Monitors** — filtered view with informational `tmsh`
   commands.
8. **Manual Review** — objects touched by dynamic logic, with the
   iRule/policy that causes the doubt.

Color coding: red = ORPHAN · yellow = MANUAL REVIEW / UNRELIABLE ·
orange = INACTIVE · purple = OFFLINE · green = IN USE.

### Change-request columns (Inventory)

Based on the row's **node verdict**, the Inventory sheet fills four
columns with informational tmsh text (bare, for a `tmsh` shell) to paste
into the change request. Nothing is generated as a script and nothing is
executed.

| Column | `OFFLINE (decommission candidate)` | `ORPHAN` |
|---|---|---|
| X `Remove node from pool` | `modify ltm pool <pool> members delete { <node>:<port> }` | — (no pool) |
| Y `Delete node` | `delete ltm node <node>` | same |
| Z `Create node (rollback)` | `create ltm node <node> address <ip>` | same |
| AA `Add node back to pool (rollback)` | `modify ltm pool <pool> members add { <node>:<port> }` | — (no pool) |

Every other verdict, `MANUAL REVIEW` and `UNRELIABLE` included, leaves the
four cells blank. Details:

- An `OFFLINE` node in several pools gets one row per pool. Run every
  `members delete` line for that node first: `delete ltm node` fails
  while the node is still a pool member.
- The rollback restores what lives on the deleted objects: the node's own
  monitor (`... monitor <monitor>`) when it is not `default`, and the
  member's `{ priority-group N }` when N > 0. Pool monitors live on the
  pool and need no rollback.
- A node named by its IPv6 literal uses `.` before the port
  (`/Common/2001:db8::10.443`); FQDN nodes are recreated with
  `fqdn { name <host> }` instead of `address`.

### Network context columns (Inventory, Orphan Nodes)

Every collection also reads the F5's own network tables — self-IPs
(`net/self`), the static ARP entries (`net/arp`) and the dynamic ARP
table (`net/arp/stats`), all plain GETs — and appends two informational
columns per node:

- **ARP MAC** — the node's MAC address when it appears in the ARP table.
- **Network note** — one of: `in ARP table (MAC ...)` (the host answered
  ARP recently, so it existed at collection time); `on local subnet, no
  ARP entry (idle or down)` (directly connected per the self-IP subnets,
  but silent); `not directly connected (behind a router)` (the F5 would
  never have an ARP entry for it); or a degradation note (FQDN node,
  IPv6 address, self-IP data unavailable, `network data not collected`
  for caches from older versions).

An orphan node that is also absent from ARP makes a safer deletion
conversation — but these columns never change a verdict.

## Development

```
pip install -e ".[dev]"
ruff check f5audit tests && ruff format --check f5audit tests
pytest
```

No test touches the network; everything runs from anonymized JSON
fixtures and mocked HTTP sessions. Structural tests assert the client
exposes no write verbs and that no forbidden endpoint appears in the
source. CI runs lint plus the test suite on Python 3.9 through 3.14;
all checks must pass before a PR can merge.

Releases are published to PyPI automatically: bump `__version__` in
`f5audit/__init__.py`, merge, and create a GitHub release tagged
`v<version>`. The release workflow verifies the tag matches the package
version, builds, and publishes via PyPI Trusted Publishing (no stored
API tokens).
