"""Verdict rules.

Cross-cutting rules (spec section 8):
- No object touched by dynamic pool-selection logic can ever be ORPHAN;
  the ceiling is MANUAL REVIEW.
- Traffic-based verdicts are only trusted when the device is ACTIVE;
  on a standby unit they are either skipped (default) or emitted as
  UNRELIABLE (standby) with --allow-standby.
- Availability-based verdicts (OFFLINE dead chains) follow the same
  standby rule: monitor results are per-unit and can differ from the
  active unit, so they are only trusted on the ACTIVE device.
- Availability is point-in-time: an offline chain may be maintenance,
  not decommissioning. Every monitor-based OFFLINE note says so.
- A pool with no members is dead by configuration, not by monitor state:
  it can load-balance to nothing. It joins the dead-pool set only when its
  members subcollection was actually collected (a denied or missing
  /members dataset is unknown, never empty), and it still goes through
  the same standby, dynamic-iRule and iApp degradations as any OFFLINE.
- Incomplete inventory (denied partitions/endpoints) degrades orphan
  verdicts, because a reference could live in an invisible partition.
- Objects owned by an iApp (nodes, pools, virtual servers) are capped at
  MANUAL REVIEW: with strict updates tmsh refuses to modify them, and
  without it the next iApp reconfigure recreates them, so removal is an
  iApp change, never a tmsh cleanup.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .correlator import Correlation, is_builtin_monitor
from .parsing import ParsedData


class Verdict:
    ORPHAN = "ORPHAN"
    MANUAL_REVIEW = "MANUAL REVIEW"
    INACTIVE = "INACTIVE"
    OFFLINE_CANDIDATE = "OFFLINE (decommission candidate)"
    UNRELIABLE_STANDBY = "UNRELIABLE (standby)"
    UNRELIABLE_INVENTORY = "UNRELIABLE (incomplete inventory)"
    IN_USE = "IN USE"


# Member availability values that count as dead-chain evidence.
# 'user-down' is an admin forced-offline: itself decommission evidence.
DEAD_MEMBER_STATES = {"offline", "down", "user-down"}
# Node-level availability values meaning "no node-level monitor result";
# for these nodes the dead-chain rule falls back to member evidence.
UNMONITORED_NODE_STATES = {"", "unknown", "unchecked"}

# Removal-candidate verdicts that the iApp ceiling degrades.
IAPP_CAPPED_VERDICTS = {Verdict.ORPHAN, Verdict.OFFLINE_CANDIDATE, Verdict.INACTIVE}

POINT_IN_TIME_NOTE = (
    "Availability is point-in-time; confirm with the config owner that this is not maintenance."
)


@dataclass
class ObjectVerdict:
    verdict: str
    notes: str = ""


@dataclass
class ManualReviewItem:
    object_type: str
    full_path: str
    reason: str
    caused_by: str = ""


@dataclass
class AnalysisResult:
    node_verdicts: dict[str, ObjectVerdict] = field(default_factory=dict)
    pool_verdicts: dict[str, ObjectVerdict] = field(default_factory=dict)
    virtual_verdicts: dict[str, ObjectVerdict] = field(default_factory=dict)
    monitor_verdicts: dict[str, ObjectVerdict] = field(default_factory=dict)
    manual_review: list[ManualReviewItem] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats_analysis_skipped: bool = False
    # Pools whose whole chain is dead (empty, or monitor-offline), whatever
    # verdict that evidence finally received (OFFLINE, or its MANUAL REVIEW / standby
    # degradation). Drives the Dead Chains sheet.
    offline_pools: set[str] = field(default_factory=set)

    def verdict_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for verdicts in (
            self.node_verdicts,
            self.pool_verdicts,
            self.virtual_verdicts,
            self.monitor_verdicts,
        ):
            for object_verdict in verdicts.values():
                counts[object_verdict.verdict] = counts.get(object_verdict.verdict, 0) + 1
        return counts


def _conns_zero(total_conns: int | None) -> bool:
    return total_conns is not None and int(total_conns) == 0


def _pool_is_empty(pool) -> bool:
    return pool.members_collected and not pool.members


def _pool_is_dead(pool) -> bool:
    """Pool with no members, or offline with every member down.
    availability is only ever populated from ltm/pool/stats, so a missing
    stats endpoint self-gates the monitor rule (empty string is never
    'offline')."""
    if _pool_is_empty(pool):
        return True
    if pool.availability != "offline" or not pool.members:
        return False
    return all(member.availability in DEAD_MEMBER_STATES for member in pool.members)


def _dead_pool_note(pool) -> str:
    if _pool_is_empty(pool):
        return (
            "Pool has no members: it cannot load-balance to anything. "
            "Configuration fact, not a point-in-time monitor state."
        )
    members_desc = ", ".join(
        f"{member.node_full_path}:{member.port} ({member.availability})" for member in pool.members
    )
    return (
        f"Pool offline: all {len(pool.members)} member(s) down "
        f"({members_desc}). " + POINT_IN_TIME_NOTE
    )


class Analyzer:
    def __init__(
        self, parsed: ParsedData, correlation: Correlation, *, allow_standby: bool = False
    ):
        self.parsed = parsed
        self.correlation = correlation
        self.allow_standby = allow_standby

        system = parsed.system
        self.is_standby = system.failover_state == "standby"
        self.inventory_complete = not system.partitions_denied and not any(
            "/ltm/node" in ep or "/ltm/pool" in ep or "/ltm/virtual" in ep
            for ep in system.missing_endpoints
        )
        self.irules_available = not any("/ltm/rule" in ep for ep in system.missing_endpoints)
        # Uptime context: traffic counters reset on reboot / stats reset.
        self.traffic_note = (
            "Traffic counters reset on reboot/stats-reset; "
            f"{system.uptime or 'device uptime unknown'}."
        )
        self._dead_pools = {path for path, pool in parsed.pools.items() if _pool_is_dead(pool)}

    # ------------------------------------------------------------------

    def run(self) -> AnalysisResult:
        result = AnalysisResult()
        self._collect_warnings(result)
        self._analyze_nodes(result)
        self._analyze_virtuals(result)
        self._analyze_pools(result)
        self._analyze_monitors(result)
        self._analyze_irules(result)
        # Last, so the ceiling applies over every rule above.
        self._apply_iapp_cap(result)
        return result

    def _collect_warnings(self, result: AnalysisResult) -> None:
        system = self.parsed.system
        if self.is_standby:
            if self.allow_standby:
                result.warnings.append(
                    "Device is STANDBY: traffic statistics and monitor "
                    "availability are not representative. Traffic- and "
                    "availability-based verdicts are marked "
                    "UNRELIABLE (standby). Re-run against the ACTIVE unit."
                )
            else:
                result.stats_analysis_skipped = True
                result.warnings.append(
                    "Device is STANDBY: traffic- and availability-based "
                    "analysis was SKIPPED (configuration-orphan analysis "
                    "still ran). Re-run against the ACTIVE unit, or use "
                    "--allow-standby to force those verdicts marked as "
                    "UNRELIABLE."
                )
        if system.partitions_denied:
            result.warnings.append(
                "Access denied to partition(s): "
                + ", ".join(system.partitions_denied)
                + ". Orphan verdicts are degraded to UNRELIABLE (incomplete "
                "inventory) because objects could be referenced from an "
                "invisible partition."
            )
        if not self.irules_available:
            result.warnings.append(
                "ltm/rule was not readable: pool orphan verdicts are capped "
                "at MANUAL REVIEW (an iRule could reference them)."
            )
        for endpoint in system.missing_endpoints:
            if "/ltm/rule" not in endpoint:
                result.warnings.append(f"Endpoint not collected: {endpoint}")

    # ------------------------------------------------------------------

    def _analyze_nodes(self, result: AnalysisResult) -> None:
        for path, node in self.parsed.nodes.items():
            pools = self.correlation.node_to_pools.get(path)
            if pools:
                if all(pool_path in self._dead_pools for pool_path in pools):
                    evidence = self._node_offline_evidence(path, node, pools)
                    if evidence and self._offline_verdict(
                        result,
                        result.node_verdicts,
                        "node",
                        path,
                        evidence,
                        # Dynamic iRules select pools, never nodes, and do
                        # not change pool membership: removing a down member
                        # from a dead pool alters nothing at runtime. The
                        # cap belongs to the pool verdict only.
                        dynamic_irules=set(),
                    ):
                        continue
                elif node.availability == "offline":
                    live = sorted(p for p in pools if p not in self._dead_pools)
                    result.node_verdicts[path] = ObjectVerdict(
                        Verdict.IN_USE,
                        "Node reports offline, but is a member of pool(s) "
                        f"{', '.join(live)} that are not offline; in use "
                        "elsewhere, not a decommission candidate.",
                    )
                    continue
                result.node_verdicts[path] = ObjectVerdict(Verdict.IN_USE)
            elif not self.inventory_complete:
                result.node_verdicts[path] = ObjectVerdict(
                    Verdict.UNRELIABLE_INVENTORY,
                    "Not a member of any visible pool, but some partitions were not readable.",
                )
            else:
                result.node_verdicts[path] = ObjectVerdict(
                    Verdict.ORPHAN, "Not a member of any pool."
                )

    def _node_offline_evidence(self, path: str, node, pools) -> str:
        """Evidence string when a node in an all-dead-pools set is itself a
        decommission candidate; empty string when it is not provable."""
        pool_list = ", ".join(sorted(pools))
        if node.availability == "offline":
            return (
                f"Node reports offline (monitor status: "
                f"{node.monitor_status or 'unknown'}); every pool membership "
                f"({pool_list}) is an offline pool. " + POINT_IN_TIME_NOTE
            )
        if node.availability in UNMONITORED_NODE_STATES:
            memberships = [
                member
                for pool_path in pools
                for member in self.parsed.pools[pool_path].members
                if member.node_full_path == path
            ]
            if memberships and all(
                member.availability in DEAD_MEMBER_STATES for member in memberships
            ):
                return (
                    "No node-level monitor result, but every pool membership "
                    f"({pool_list}) reports down/offline and every containing "
                    "pool is offline. " + POINT_IN_TIME_NOTE
                )
        return ""

    def _virtual_is_dead(self, path: str, virtual) -> bool:
        if path in self.correlation.virtuals_with_unprovable_pool_selection:
            return False
        reachable = self.correlation.virtual_to_pools.get(path)
        if not reachable:
            return False
        if not all(
            pool_path in self.parsed.pools and pool_path in self._dead_pools
            for pool_path in reachable
        ):
            return False
        # BIG-IP reports a virtual whose pools are all empty as 'unknown',
        # not 'offline': the empty pools are the evidence by themselves.
        if all(_pool_is_empty(self.parsed.pools[pool_path]) for pool_path in reachable):
            return True
        return virtual.availability == "offline"

    def _dead_pools_note(self, pool_paths) -> str:
        pools = ", ".join(sorted(pool_paths))
        empty = [_pool_is_empty(self.parsed.pools[pool_path]) for pool_path in pool_paths]
        if all(empty):
            return f"every reachable pool ({pools}) has no members."
        state = "has no members or is offline" if any(empty) else "is offline"
        note = f"every reachable pool ({pools}) {state} with all members down. "
        return note + POINT_IN_TIME_NOTE

    def _offline_verdict(
        self,
        result: AnalysisResult,
        verdicts: dict[str, ObjectVerdict],
        object_type: str,
        path: str,
        note: str,
        *,
        dynamic_irules: set[str],
    ) -> bool:
        """Emit an availability-based OFFLINE verdict, degraded on standby
        and capped at MANUAL REVIEW when `dynamic_irules` (the attached
        dynamic iRules that can reach the object) is non-empty.
        Returns False when skipped so the caller falls through to the
        existing rules."""
        if self.is_standby:
            if not self.allow_standby:
                return False
            verdicts[path] = ObjectVerdict(
                Verdict.UNRELIABLE_STANDBY,
                "Offline on this device, but it is standby and monitor "
                "state may differ from the active unit. " + note,
            )
            return True
        if dynamic_irules:
            dynamic = ", ".join(sorted(dynamic_irules))
            verdicts[path] = ObjectVerdict(
                Verdict.MANUAL_REVIEW,
                note + " Dynamic pool-selection iRules are active "
                f"({dynamic}); the object could still be selected at runtime.",
            )
            result.manual_review.append(
                ManualReviewItem(
                    object_type,
                    path,
                    "Offline decommission candidate, but dynamic iRules are active",
                    dynamic,
                )
            )
            return True
        verdicts[path] = ObjectVerdict(Verdict.OFFLINE_CANDIDATE, note)
        return True

    def _analyze_virtuals(self, result: AnalysisResult) -> None:
        for path, virtual in self.parsed.virtuals.items():
            if virtual.admin_state == "disabled":
                result.virtual_verdicts[path] = ObjectVerdict(
                    Verdict.INACTIVE, "Administratively disabled."
                )
                continue
            if not virtual.default_pool and (virtual.irules or virtual.policies):
                result.virtual_verdicts[path] = ObjectVerdict(
                    Verdict.MANUAL_REVIEW,
                    "No default pool; traffic is steered by iRules/policies.",
                )
                result.manual_review.append(
                    ManualReviewItem(
                        "virtual_server",
                        path,
                        "No default pool but has iRules/policies attached",
                        ", ".join(virtual.irules + virtual.policies),
                    )
                )
                continue
            if self._virtual_is_dead(path, virtual):
                emitted = self._offline_verdict(
                    result,
                    result.virtual_verdicts,
                    "virtual_server",
                    path,
                    "Offline: " + self._dead_pools_note(self.correlation.virtual_to_pools[path]),
                    # The VS's own pool selection is provably static and dead;
                    # dynamic iRules on other virtual servers do not change
                    # whether this VS can serve traffic.
                    dynamic_irules=set(),
                )
                if emitted:
                    continue
            if _conns_zero(virtual.total_conns):
                self._traffic_verdict(
                    result.virtual_verdicts,
                    path,
                    "Enabled but zero total connections. " + self.traffic_note,
                )
                continue
            result.virtual_verdicts[path] = ObjectVerdict(Verdict.IN_USE)

    def _traffic_verdict(self, verdicts: dict[str, ObjectVerdict], path: str, note: str) -> None:
        """Emit a traffic-based INACTIVE verdict, degraded on standby."""
        if self.is_standby:
            if self.allow_standby:
                verdicts[path] = ObjectVerdict(
                    Verdict.UNRELIABLE_STANDBY,
                    "Zero traffic, but this device is standby. " + note,
                )
            else:
                verdicts[path] = ObjectVerdict(
                    Verdict.IN_USE,
                    "Traffic analysis skipped (standby device).",
                )
        else:
            verdicts[path] = ObjectVerdict(Verdict.INACTIVE, note)

    def _analyze_pools(self, result: AnalysisResult) -> None:
        for path, pool in self.parsed.pools.items():
            virtuals = self.correlation.pool_to_virtuals.get(path, set())
            irule_refs = self.correlation.pool_to_irules.get(path, set())
            policy_refs = self.correlation.pool_to_policies.get(path, set())

            # ORPHAN outranks OFFLINE: an unreferenced pool is deletable
            # without asking the config owner.
            if not virtuals and not irule_refs and not policy_refs:
                self._unreferenced_pool_verdict(result, path)
                continue

            if path in self._dead_pools:
                emitted = self._offline_verdict(
                    result,
                    result.pool_verdicts,
                    "pool",
                    path,
                    _dead_pool_note(pool),
                    dynamic_irules=self.correlation.dynamic_irules_for_pool(path),
                )
                if emitted:
                    result.offline_pools.add(path)
                    continue

            # Referenced pool: inactive if every attached VS has zero traffic.
            if (
                virtuals
                and all(
                    _conns_zero(self.parsed.virtuals[v].total_conns)
                    for v in virtuals
                    if v in self.parsed.virtuals
                )
                and any(v in self.parsed.virtuals for v in virtuals)
            ):
                self._traffic_verdict(
                    result.pool_verdicts,
                    path,
                    "All attached virtual servers have zero total "
                    "connections. " + self.traffic_note,
                )
                continue
            result.pool_verdicts[path] = ObjectVerdict(Verdict.IN_USE)

    def _unreferenced_pool_verdict(self, result: AnalysisResult, path: str) -> None:
        if not self.inventory_complete:
            result.pool_verdicts[path] = ObjectVerdict(
                Verdict.UNRELIABLE_INVENTORY,
                "No visible references, but some partitions were not readable.",
            )
        elif not self.irules_available:
            result.pool_verdicts[path] = ObjectVerdict(
                Verdict.MANUAL_REVIEW,
                "No VS/policy references; iRules could not be read "
                "(ltm/rule denied), so an iRule reference cannot be ruled out.",
            )
            result.manual_review.append(
                ManualReviewItem(
                    "pool",
                    path,
                    "Unreferenced, but ltm/rule was not readable",
                )
            )
        elif self.correlation.dynamic_irules_for_pool(path):
            dynamic = ", ".join(sorted(self.correlation.dynamic_irules_for_pool(path)))
            result.pool_verdicts[path] = ObjectVerdict(
                Verdict.MANUAL_REVIEW,
                "No static references, but dynamic pool-selection iRules "
                f"that can reach this partition are active ({dynamic}); "
                "the pool could be selected at runtime.",
            )
            result.manual_review.append(
                ManualReviewItem(
                    "pool",
                    path,
                    "No static references but dynamic iRules are active",
                    dynamic,
                )
            )
        else:
            result.pool_verdicts[path] = ObjectVerdict(
                Verdict.ORPHAN,
                "Not referenced by any virtual server, iRule or policy.",
            )

    def _analyze_monitors(self, result: AnalysisResult) -> None:
        for path, _monitor in self.parsed.monitors.items():
            if is_builtin_monitor(path):
                result.monitor_verdicts[path] = ObjectVerdict(
                    Verdict.IN_USE, "F5 built-in monitor (excluded from orphan analysis)."
                )
                continue
            users = self.correlation.monitor_users.get(path)
            if users:
                result.monitor_verdicts[path] = ObjectVerdict(Verdict.IN_USE)
            elif not self.inventory_complete:
                result.monitor_verdicts[path] = ObjectVerdict(
                    Verdict.UNRELIABLE_INVENTORY,
                    "Unused in visible partitions, but some partitions were not readable.",
                )
            else:
                result.monitor_verdicts[path] = ObjectVerdict(
                    Verdict.ORPHAN, "Not used by any node or pool."
                )

    # ------------------------------------------------------------------

    def _pool_iapp(self, path: str) -> str:
        pool = self.parsed.pools.get(path)
        if pool is None:
            return ""
        if pool.app_service:
            return pool.app_service
        return next((m.app_service for m in pool.members if m.app_service), "")

    def _node_iapp(self, path: str, node) -> str:
        if node.app_service:
            return node.app_service
        for pool_path in sorted(self.correlation.node_to_pools.get(path, set())):
            pool = self.parsed.pools.get(pool_path)
            if pool is None:
                continue
            for member in pool.members:
                if member.node_full_path == path and member.app_service:
                    return member.app_service
            owner = self._pool_iapp(pool_path)
            if owner:
                return owner
        return ""

    def _apply_iapp_cap(self, result: AnalysisResult) -> None:
        owners = [
            ("node", result.node_verdicts, path, self._node_iapp(path, node))
            for path, node in self.parsed.nodes.items()
        ]
        owners += [
            ("pool", result.pool_verdicts, path, self._pool_iapp(path))
            for path in self.parsed.pools
        ]
        owners += [
            ("virtual_server", result.virtual_verdicts, path, virtual.app_service)
            for path, virtual in self.parsed.virtuals.items()
        ]
        for object_type, verdicts, path, app_service in owners:
            current = verdicts.get(path)
            if not app_service or current is None:
                continue
            if current.verdict not in IAPP_CAPPED_VERDICTS:
                continue
            evidence = f"{current.verdict}: {current.notes}" if current.notes else current.verdict
            verdicts[path] = ObjectVerdict(
                Verdict.MANUAL_REVIEW,
                f"Owned by iApp {app_service}; tmsh cannot modify it (strict "
                "updates), change it through the iApp. Underlying evidence: "
                f"{evidence}",
            )
            result.manual_review.append(
                ManualReviewItem(object_type, path, "Owned by an iApp", app_service)
            )

    def _analyze_irules(self, result: AnalysisResult) -> None:
        for path, irule in self.parsed.irules.items():
            if irule.has_dynamic_pool_selection:
                result.manual_review.append(
                    ManualReviewItem(
                        "irule",
                        path,
                        "Selects pools dynamically ($variable, [command] or "
                        "datagroup); static analysis cannot resolve its targets",
                    )
                )
