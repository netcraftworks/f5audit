"""Verdict rule tests: every rule with positive and negative cases."""

from f5audit.analyzer import POINT_IN_TIME_NOTE, Analyzer, Verdict
from f5audit.correlator import correlate
from f5audit.models import IRule, Policy, Pool, PoolMember, VirtualServer
from f5audit.parsing import parse_collection
from tests.conftest import build_collection


def analyze(
    *, standby=False, allow_standby=False, denied=None, missing_endpoints=None, mutate=None
):
    parsed = parse_collection(
        build_collection(
            standby=standby,
            denied=denied,
            missing_endpoints=missing_endpoints,
        )
    )
    if mutate:
        mutate(parsed)
    correlation = correlate(parsed)
    analyzer = Analyzer(parsed, correlation, allow_standby=allow_standby)
    return analyzer.run()


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


def test_node_without_pool_is_orphan():
    result = analyze()
    assert result.node_verdicts["/Common/node-orphan"].verdict == Verdict.ORPHAN


def test_node_in_pool_is_in_use():
    result = analyze()
    assert result.node_verdicts["/Common/node-web-1"].verdict == Verdict.IN_USE


def test_node_orphan_degraded_when_partition_denied():
    result = analyze(denied=[{"partition": "Secret", "endpoint": "/mgmt/tm/ltm/pool"}])
    assert result.node_verdicts["/Common/node-orphan"].verdict == Verdict.UNRELIABLE_INVENTORY
    # A node that IS in a visible pool stays IN USE regardless.
    assert result.node_verdicts["/Common/node-web-1"].verdict == Verdict.IN_USE


# ---------------------------------------------------------------------------
# Pools
# ---------------------------------------------------------------------------


def test_unreferenced_pool_is_orphan():
    result = analyze()
    assert result.pool_verdicts["/Common/pool-orphan"].verdict == Verdict.ORPHAN


def test_pool_referenced_by_irule_is_in_use():
    result = analyze()
    assert result.pool_verdicts["/Common/pool-irule"].verdict == Verdict.IN_USE


def test_pool_with_traffic_is_in_use():
    result = analyze()
    assert result.pool_verdicts["/Common/pool-web"].verdict == Verdict.IN_USE


def test_pool_with_only_idle_virtuals_is_inactive():
    result = analyze()
    assert result.pool_verdicts["/Common/pool-idle"].verdict == Verdict.INACTIVE


def attach_dynamic_irule(parsed):
    parsed.irules["/Common/irule-dyn"] = IRule(
        full_path="/Common/irule-dyn",
        partition="Common",
        name="irule-dyn",
        definition="pool $x",
        has_dynamic_pool_selection=True,
    )
    parsed.virtuals["/Common/vs-web"].irules.append("/Common/irule-dyn")


def test_dynamic_irule_caps_orphan_pool_at_manual_review():
    result = analyze(mutate=attach_dynamic_irule)
    verdict = result.pool_verdicts["/Common/pool-orphan"]
    assert verdict.verdict == Verdict.MANUAL_REVIEW
    assert "/Common/irule-dyn" in verdict.notes
    # Statically referenced pools are unaffected.
    assert result.pool_verdicts["/Common/pool-irule"].verdict == Verdict.IN_USE
    # And the dynamic iRule itself lands in the manual review sheet.
    assert any(
        item.object_type == "irule" and item.full_path == "/Common/irule-dyn"
        for item in result.manual_review
    )


def attach_dynamic_irule_in_other_partition(parsed):
    """Dynamic iRule attached to a VS in /PartA, with no literal path to
    /Common or elsewhere: it can only reach /PartA and /Common pools."""
    parsed.irules["/PartA/irule-dyn"] = IRule(
        full_path="/PartA/irule-dyn",
        partition="PartA",
        name="irule-dyn",
        definition="pool $x",
        has_dynamic_pool_selection=True,
    )
    parsed.virtuals["/PartA/vs-a"] = VirtualServer(
        full_path="/PartA/vs-a",
        partition="PartA",
        name="vs-a",
        irules=["/PartA/irule-dyn"],
    )


def move_dead_chain_to_partition_b(parsed):
    """Re-home pool-dead (and its VS) in /PartB; node-dead keeps its path."""
    pool = parsed.pools.pop("/Common/pool-dead")
    pool.full_path, pool.partition = "/PartB/pool-dead", "PartB"
    parsed.pools[pool.full_path] = pool
    virtual = parsed.virtuals["/Common/vs-dead"]
    virtual.default_pool = pool.full_path


def test_dynamic_irule_in_other_partition_does_not_cap_unreferenced_pool():
    def mutate(parsed):
        attach_dynamic_irule_in_other_partition(parsed)
        parsed.pools["/PartB/pool-unused"] = Pool(
            full_path="/PartB/pool-unused", partition="PartB", name="pool-unused"
        )

    result = analyze(mutate=mutate)
    assert result.pool_verdicts["/PartB/pool-unused"].verdict == Verdict.ORPHAN
    # /Common is always in reach of any attached dynamic iRule.
    verdict = result.pool_verdicts["/Common/pool-orphan"]
    assert verdict.verdict == Verdict.MANUAL_REVIEW
    assert "/PartA/irule-dyn" in verdict.notes


def test_missing_ltm_rule_endpoint_caps_orphan_pool_at_manual_review():
    result = analyze(missing_endpoints=["/mgmt/tm/ltm/rule"])
    assert result.pool_verdicts["/Common/pool-orphan"].verdict == Verdict.MANUAL_REVIEW
    assert any("MANUAL REVIEW" in warning for warning in result.warnings)


# ---------------------------------------------------------------------------
# Virtual servers
# ---------------------------------------------------------------------------


def test_disabled_virtual_is_inactive():
    result = analyze()
    assert result.virtual_verdicts["/Common/vs-disabled"].verdict == Verdict.INACTIVE


def test_zero_conns_virtual_is_inactive():
    result = analyze()
    verdict = result.virtual_verdicts["/Common/vs-idle"]
    assert verdict.verdict == Verdict.INACTIVE
    # Traffic-based verdicts must carry the uptime context.
    assert "reset" in verdict.notes


def test_virtual_with_traffic_is_in_use():
    result = analyze()
    assert result.virtual_verdicts["/Common/vs-web"].verdict == Verdict.IN_USE


def test_virtual_without_pool_but_with_irules_is_manual_review():
    def mutate(parsed):
        parsed.virtuals["/Common/vs-web"].default_pool = ""

    result = analyze(mutate=mutate)
    assert result.virtual_verdicts["/Common/vs-web"].verdict == Verdict.MANUAL_REVIEW


# ---------------------------------------------------------------------------
# Dead chains (OFFLINE decommission candidates)
# ---------------------------------------------------------------------------


def test_dead_chain_flags_virtual_pool_and_node_offline():
    result = analyze()
    assert result.virtual_verdicts["/Common/vs-dead"].verdict == Verdict.OFFLINE_CANDIDATE
    assert result.pool_verdicts["/Common/pool-dead"].verdict == Verdict.OFFLINE_CANDIDATE
    assert result.node_verdicts["/Common/node-dead"].verdict == Verdict.OFFLINE_CANDIDATE
    # Notes carry the evidence chain and the point-in-time caveat.
    assert "/Common/pool-dead" in result.virtual_verdicts["/Common/vs-dead"].notes
    assert "node-dead:443" in result.pool_verdicts["/Common/pool-dead"].notes
    for verdicts, path in (
        (result.virtual_verdicts, "/Common/vs-dead"),
        (result.pool_verdicts, "/Common/pool-dead"),
        (result.node_verdicts, "/Common/node-dead"),
    ):
        assert "point-in-time" in verdicts[path].notes


def test_dead_chain_overrides_historical_traffic():
    # vs-dead has 4321 total conns in the fixture: traffic alone would say
    # IN USE, but the chain is offline now.
    result = analyze()
    verdict = result.virtual_verdicts["/Common/vs-dead"]
    assert verdict.verdict == Verdict.OFFLINE_CANDIDATE


def down_member(node_path, port):
    return PoolMember(
        node_full_path=node_path,
        port=port,
        partition="Common",
        admin_state="monitor-enabled",
        availability="offline",
    )


def share_dead_node_with_live_pool(parsed):
    parsed.pools["/Common/pool-web"].members.append(
        PoolMember(
            node_full_path="/Common/node-dead",
            port="80",
            partition="Common",
            admin_state="monitor-enabled",
            availability="available",
        )
    )


def test_node_offline_but_alive_in_another_pool_is_in_use():
    result = analyze(mutate=share_dead_node_with_live_pool)
    node_verdict = result.node_verdicts["/Common/node-dead"]
    assert node_verdict.verdict == Verdict.IN_USE
    assert "in use elsewhere" in node_verdict.notes


def test_dead_pool_with_node_alive_in_another_pool_is_manual_review():
    result = analyze(mutate=share_dead_node_with_live_pool)
    pool_verdict = result.pool_verdicts["/Common/pool-dead"]
    assert pool_verdict.verdict == Verdict.MANUAL_REVIEW
    assert "Pool offline" in pool_verdict.notes
    assert "/Common/node-dead: also a member of live pool(s) /Common/pool-web" in (
        pool_verdict.notes
    )
    # Still a dead chain: it stays on the Dead Chains sheet.
    assert "/Common/pool-dead" in result.offline_pools
    # The hold propagates to the virtual server, naming the pool behind it.
    virtual_verdict = result.virtual_verdicts["/Common/vs-dead"]
    assert virtual_verdict.verdict == Verdict.MANUAL_REVIEW
    assert "pool /Common/pool-dead has member node(s) still IN USE" in virtual_verdict.notes
    for object_type, path in (("pool", "/Common/pool-dead"), ("virtual_server", "/Common/vs-dead")):
        assert any(
            item.object_type == object_type
            and item.full_path == path
            and item.caused_by == "/Common/node-dead"
            for item in result.manual_review
        )


def test_dead_pool_with_node_answering_its_node_monitor_is_manual_review():
    def mutate(parsed):
        # Server up (node-level monitor passes), service on the port down.
        parsed.nodes["/Common/node-dead"].availability = "available"

    result = analyze(mutate=mutate)
    assert result.node_verdicts["/Common/node-dead"].verdict == Verdict.IN_USE
    pool_verdict = result.pool_verdicts["/Common/pool-dead"]
    assert pool_verdict.verdict == Verdict.MANUAL_REVIEW
    assert "answers its node-level monitor (availability: available)" in pool_verdict.notes
    assert result.virtual_verdicts["/Common/vs-dead"].verdict == Verdict.MANUAL_REVIEW


def test_dead_node_stays_offline_inside_pool_held_by_another_node():
    def mutate(parsed):
        share_dead_node_with_live_pool(parsed)
        # node-orphan has no node-level monitor and lives only in pool-dead.
        parsed.pools["/Common/pool-dead"].members.append(down_member("/Common/node-orphan", "443"))

    result = analyze(mutate=mutate)
    assert result.node_verdicts["/Common/node-orphan"].verdict == Verdict.OFFLINE_CANDIDATE
    assert result.node_verdicts["/Common/node-dead"].verdict == Verdict.IN_USE
    pool_verdict = result.pool_verdicts["/Common/pool-dead"]
    assert pool_verdict.verdict == Verdict.MANUAL_REVIEW
    assert "/Common/node-orphan:" not in pool_verdict.notes.split("Held at MANUAL REVIEW")[1]


def kill_idle_pool(parsed):
    """The vs-idle chain goes monitor-dead; its node-web-1 lives on in pool-web."""
    pool = parsed.pools["/Common/pool-idle"]
    pool.availability = "offline"
    pool.members[0].availability = "offline"
    parsed.virtuals["/Common/vs-idle"].availability = "offline"


def test_virtual_reaching_one_held_pool_among_dead_pools_is_manual_review():
    def mutate(parsed):
        kill_idle_pool(parsed)
        parsed.irules["/Common/irule-idle"] = IRule(
            full_path="/Common/irule-idle",
            partition="Common",
            name="irule-idle",
            definition="pool pool-idle",
            referenced_pools=["/Common/pool-idle"],
        )
        parsed.virtuals["/Common/vs-dead"].irules.append("/Common/irule-idle")

    result = analyze(mutate=mutate)
    # pool-dead itself has no IN USE node: it is held only because its
    # virtual server now carries an iRule.
    pool_dead = result.pool_verdicts["/Common/pool-dead"]
    assert pool_dead.verdict == Verdict.MANUAL_REVIEW
    assert "still IN USE" not in pool_dead.notes
    assert result.pool_verdicts["/Common/pool-idle"].verdict == Verdict.MANUAL_REVIEW
    virtual_verdict = result.virtual_verdicts["/Common/vs-dead"]
    assert virtual_verdict.verdict == Verdict.MANUAL_REVIEW
    assert "pool /Common/pool-idle has member node(s) still IN USE" in virtual_verdict.notes
    assert "pool /Common/pool-dead has member" not in virtual_verdict.notes


def test_held_pool_does_not_hold_unrelated_dead_chain():
    result = analyze(mutate=kill_idle_pool)
    assert result.pool_verdicts["/Common/pool-idle"].verdict == Verdict.MANUAL_REVIEW
    assert result.virtual_verdicts["/Common/vs-idle"].verdict == Verdict.MANUAL_REVIEW
    assert result.pool_verdicts["/Common/pool-dead"].verdict == Verdict.OFFLINE_CANDIDATE
    assert result.virtual_verdicts["/Common/vs-dead"].verdict == Verdict.OFFLINE_CANDIDATE


def test_unreferenced_dead_pool_with_in_use_node_stays_orphan():
    def mutate(parsed):
        pool = parsed.pools["/Common/pool-orphan"]
        pool.availability = "offline"
        pool.members.append(down_member("/Common/node-web-1", "9000"))

    result = analyze(mutate=mutate)
    assert result.node_verdicts["/Common/node-web-1"].verdict == Verdict.IN_USE
    assert result.pool_verdicts["/Common/pool-orphan"].verdict == Verdict.ORPHAN


def test_dynamic_irule_and_in_use_node_both_explain_the_manual_review():
    def mutate(parsed):
        attach_dynamic_irule(parsed)
        share_dead_node_with_live_pool(parsed)

    result = analyze(mutate=mutate)
    pool_verdict = result.pool_verdicts["/Common/pool-dead"]
    assert pool_verdict.verdict == Verdict.MANUAL_REVIEW
    assert "/Common/irule-dyn" in pool_verdict.notes
    assert "still IN USE" in pool_verdict.notes
    reasons = [
        item.reason for item in result.manual_review if item.full_path == "/Common/pool-dead"
    ]
    assert len(reasons) == 2


def test_standby_with_flag_outranks_in_use_node_hold():
    result = analyze(standby=True, allow_standby=True, mutate=share_dead_node_with_live_pool)
    assert result.pool_verdicts["/Common/pool-dead"].verdict == Verdict.UNRELIABLE_STANDBY
    assert result.virtual_verdicts["/Common/vs-dead"].verdict == Verdict.UNRELIABLE_STANDBY


def test_node_without_monitor_flagged_via_member_evidence():
    def mutate(parsed):
        parsed.nodes["/Common/node-dead"].availability = "unknown"

    result = analyze(mutate=mutate)
    verdict = result.node_verdicts["/Common/node-dead"]
    assert verdict.verdict == Verdict.OFFLINE_CANDIDATE
    assert "No node-level monitor result" in verdict.notes


def test_node_without_monitor_and_live_membership_not_flagged():
    def mutate(parsed):
        parsed.nodes["/Common/node-dead"].availability = "unknown"
        parsed.pools["/Common/pool-dead"].members[0].availability = "available"

    result = analyze(mutate=mutate)
    # The pool is no longer dead, so nothing in the chain is a candidate.
    assert result.node_verdicts["/Common/node-dead"].verdict == Verdict.IN_USE
    assert result.pool_verdicts["/Common/pool-dead"].verdict != Verdict.OFFLINE_CANDIDATE


def test_pool_not_dead_when_availability_unknown():
    def mutate(parsed):
        parsed.pools["/Common/pool-dead"].availability = "unknown"

    result = analyze(mutate=mutate)
    assert result.pool_verdicts["/Common/pool-dead"].verdict != Verdict.OFFLINE_CANDIDATE
    assert result.virtual_verdicts["/Common/vs-dead"].verdict != Verdict.OFFLINE_CANDIDATE
    assert result.node_verdicts["/Common/node-dead"].verdict == Verdict.IN_USE


def test_pool_not_dead_when_a_member_is_available():
    def mutate(parsed):
        parsed.pools["/Common/pool-dead"].members[0].availability = "available"

    result = analyze(mutate=mutate)
    assert result.pool_verdicts["/Common/pool-dead"].verdict != Verdict.OFFLINE_CANDIDATE


def test_pool_not_dead_without_pool_stats():
    def mutate(parsed):
        # Simulate a collection where ltm/pool/stats was not readable.
        for pool in parsed.pools.values():
            pool.availability = ""

    result = analyze(mutate=mutate)
    assert result.pool_verdicts["/Common/pool-dead"].verdict != Verdict.OFFLINE_CANDIDATE


def test_dynamic_irules_cap_dead_pool_but_not_its_dead_node():
    result = analyze(mutate=attach_dynamic_irule)
    pool_verdict = result.pool_verdicts["/Common/pool-dead"]
    assert pool_verdict.verdict == Verdict.MANUAL_REVIEW
    assert "Pool offline" in pool_verdict.notes
    assert "/Common/pool-dead" in result.offline_pools
    # Dynamic iRules pick pools, not nodes: the dead member stays OFFLINE.
    assert result.node_verdicts["/Common/node-dead"].verdict == Verdict.OFFLINE_CANDIDATE
    assert any(
        item.object_type == "pool" and item.full_path == "/Common/pool-dead"
        for item in result.manual_review
    )
    # The VS's own pool selection is static and provably dead: still OFFLINE.
    assert result.virtual_verdicts["/Common/vs-dead"].verdict == Verdict.OFFLINE_CANDIDATE


def test_dynamic_irule_in_other_partition_does_not_cap_dead_pool_and_node():
    def mutate(parsed):
        attach_dynamic_irule_in_other_partition(parsed)
        move_dead_chain_to_partition_b(parsed)

    result = analyze(mutate=mutate)
    assert result.pool_verdicts["/PartB/pool-dead"].verdict == Verdict.OFFLINE_CANDIDATE
    assert result.node_verdicts["/Common/node-dead"].verdict == Verdict.OFFLINE_CANDIDATE


def test_virtual_with_own_dynamic_irule_never_offline():
    def mutate(parsed):
        attach_dynamic_irule(parsed)
        parsed.virtuals["/Common/vs-dead"].irules.append("/Common/irule-dyn")

    result = analyze(mutate=mutate)
    assert result.virtual_verdicts["/Common/vs-dead"].verdict != Verdict.OFFLINE_CANDIDATE


def test_standby_without_flag_skips_offline_verdicts():
    result = analyze(standby=True)
    all_verdicts = list(result.node_verdicts.values())
    all_verdicts += list(result.pool_verdicts.values())
    all_verdicts += list(result.virtual_verdicts.values())
    assert all(v.verdict != Verdict.OFFLINE_CANDIDATE for v in all_verdicts)


def test_standby_with_flag_marks_offline_verdicts_unreliable():
    result = analyze(standby=True, allow_standby=True)
    verdict = result.pool_verdicts["/Common/pool-dead"]
    assert verdict.verdict == Verdict.UNRELIABLE_STANDBY
    assert "standby" in verdict.notes
    assert result.virtual_verdicts["/Common/vs-dead"].verdict == Verdict.UNRELIABLE_STANDBY
    assert result.node_verdicts["/Common/node-dead"].verdict == Verdict.UNRELIABLE_STANDBY


# ---------------------------------------------------------------------------
# Monitors
# ---------------------------------------------------------------------------


def test_unused_custom_monitor_is_orphan():
    result = analyze()
    assert result.monitor_verdicts["/Common/mon-orphan"].verdict == Verdict.ORPHAN


def test_used_custom_monitor_is_in_use():
    result = analyze()
    assert result.monitor_verdicts["/Common/mon-used"].verdict == Verdict.IN_USE


def test_builtin_monitor_never_orphan():
    result = analyze()
    # /Common/http is unused in the fixture but is an F5 factory monitor.
    assert result.monitor_verdicts["/Common/http"].verdict == Verdict.IN_USE


# ---------------------------------------------------------------------------
# Standby handling
# ---------------------------------------------------------------------------


def test_standby_without_flag_skips_traffic_verdicts():
    result = analyze(standby=True)
    assert result.stats_analysis_skipped is True
    assert any("STANDBY" in warning for warning in result.warnings)
    # Traffic-based rules are skipped: nothing gets INACTIVE from zero conns.
    assert result.virtual_verdicts["/Common/vs-idle"].verdict == Verdict.IN_USE
    assert result.pool_verdicts["/Common/pool-idle"].verdict == Verdict.IN_USE
    # Config-based rules still run.
    assert result.node_verdicts["/Common/node-orphan"].verdict == Verdict.ORPHAN
    assert result.pool_verdicts["/Common/pool-orphan"].verdict == Verdict.ORPHAN
    assert result.virtual_verdicts["/Common/vs-disabled"].verdict == Verdict.INACTIVE


def test_standby_with_flag_marks_traffic_verdicts_unreliable():
    result = analyze(standby=True, allow_standby=True)
    assert result.stats_analysis_skipped is False
    assert result.virtual_verdicts["/Common/vs-idle"].verdict == Verdict.UNRELIABLE_STANDBY
    assert result.pool_verdicts["/Common/pool-idle"].verdict == Verdict.UNRELIABLE_STANDBY
    # Never ORPHAN from traffic data on a standby unit.
    assert result.virtual_verdicts["/Common/vs-web"].verdict == Verdict.UNRELIABLE_STANDBY


def test_active_device_with_traffic_has_no_standby_warnings():
    result = analyze()
    assert not any("STANDBY" in warning for warning in result.warnings)


# ---------------------------------------------------------------------------
# iApp ownership ceiling
# ---------------------------------------------------------------------------

IAPP = "/Common/adfs.app/adfs"


def own_dead_chain_by_member(parsed):
    # appService only on the pool member, as BIG-IP reports it for iApp pools.
    for member in parsed.pools["/Common/pool-dead"].members:
        member.app_service = IAPP


def test_iapp_member_caps_dead_node_and_pool_at_manual_review():
    result = analyze(mutate=own_dead_chain_by_member)
    node = result.node_verdicts["/Common/node-dead"]
    assert node.verdict == Verdict.MANUAL_REVIEW
    assert IAPP in node.notes
    assert Verdict.OFFLINE_CANDIDATE in node.notes  # underlying evidence kept
    pool = result.pool_verdicts["/Common/pool-dead"]
    assert pool.verdict == Verdict.MANUAL_REVIEW
    assert "/Common/pool-dead" in result.offline_pools  # still a dead chain
    caused_by = {(i.object_type, i.full_path): i.caused_by for i in result.manual_review}
    assert caused_by[("node", "/Common/node-dead")] == IAPP
    assert caused_by[("pool", "/Common/pool-dead")] == IAPP


def test_dead_chain_without_iapp_stays_offline():
    result = analyze()
    assert result.node_verdicts["/Common/node-dead"].verdict == Verdict.OFFLINE_CANDIDATE
    assert not any(i.reason == "Owned by an iApp" for i in result.manual_review)


def test_iapp_unreferenced_pool_is_not_orphan():
    def own(parsed):
        parsed.pools["/Common/pool-orphan"].app_service = IAPP

    result = analyze(mutate=own)
    assert result.pool_verdicts["/Common/pool-orphan"].verdict == Verdict.MANUAL_REVIEW


def test_iapp_node_without_pool_is_not_orphan():
    def own(parsed):
        parsed.nodes["/Common/node-orphan"].app_service = IAPP

    result = analyze(mutate=own)
    assert result.node_verdicts["/Common/node-orphan"].verdict == Verdict.MANUAL_REVIEW


def test_iapp_idle_virtual_is_not_inactive():
    def own(parsed):
        parsed.virtuals["/Common/vs-idle"].app_service = IAPP

    result = analyze(mutate=own)
    verdict = result.virtual_verdicts["/Common/vs-idle"]
    assert verdict.verdict == Verdict.MANUAL_REVIEW
    assert "reset" in verdict.notes  # counter-reset context survives the cap


def test_iapp_in_use_objects_stay_in_use():
    def own(parsed):
        parsed.pools["/Common/pool-web"].app_service = IAPP

    result = analyze(mutate=own)
    assert result.pool_verdicts["/Common/pool-web"].verdict == Verdict.IN_USE
    assert result.node_verdicts["/Common/node-web-1"].verdict == Verdict.IN_USE


# ---------------------------------------------------------------------------
# Empty pools
# ---------------------------------------------------------------------------


def empty_pool(path):
    def mutate(parsed):
        parsed.pools[path].members = []

    return mutate


def test_parsed_pool_records_whether_members_were_collected():
    parsed = parse_collection(build_collection())
    assert parsed.pools["/Common/pool-web"].members_collected
    collection = build_collection()
    del collection.datasets["ltm_pool_members@/Common/pool-idle"]
    parsed = parse_collection(collection)
    assert not parsed.pools["/Common/pool-idle"].members_collected


def test_empty_referenced_pool_is_offline():
    result = analyze(mutate=empty_pool("/Common/pool-idle"))
    verdict = result.pool_verdicts["/Common/pool-idle"]
    assert verdict.verdict == Verdict.OFFLINE_CANDIDATE
    assert "no members" in verdict.notes
    assert POINT_IN_TIME_NOTE not in verdict.notes
    assert "/Common/pool-idle" in result.offline_pools


def test_pool_with_uncollected_members_is_not_offline():
    def mutate(parsed):
        pool = parsed.pools["/Common/pool-idle"]
        pool.members = []
        pool.members_collected = False

    result = analyze(mutate=mutate)
    assert result.pool_verdicts["/Common/pool-idle"].verdict != Verdict.OFFLINE_CANDIDATE
    assert "/Common/pool-idle" not in result.offline_pools


def test_empty_unreferenced_pool_stays_orphan():
    result = analyze(mutate=empty_pool("/Common/pool-orphan"))
    assert result.pool_verdicts["/Common/pool-orphan"].verdict == Verdict.ORPHAN


def test_empty_pool_reachable_by_dynamic_irule_is_manual_review():
    def mutate(parsed):
        empty_pool("/Common/pool-idle")(parsed)
        parsed.irules["/Common/irule-dyn"] = IRule(
            full_path="/Common/irule-dyn",
            partition="Common",
            name="irule-dyn",
            definition="pool $x",
            has_dynamic_pool_selection=True,
        )
        parsed.virtuals["/Common/vs-web"].irules.append("/Common/irule-dyn")

    result = analyze(mutate=mutate)
    assert result.pool_verdicts["/Common/pool-idle"].verdict == Verdict.MANUAL_REVIEW


def test_iapp_empty_pool_is_manual_review():
    def mutate(parsed):
        empty_pool("/Common/pool-idle")(parsed)
        parsed.pools["/Common/pool-idle"].app_service = IAPP

    result = analyze(mutate=mutate)
    assert result.pool_verdicts["/Common/pool-idle"].verdict == Verdict.MANUAL_REVIEW


def test_virtual_whose_only_pool_is_empty_is_offline_despite_unknown_availability():
    result = analyze(mutate=empty_pool("/Common/pool-idle"))
    verdict = result.virtual_verdicts["/Common/vs-idle"]
    assert verdict.verdict == Verdict.OFFLINE_CANDIDATE
    assert "has no members" in verdict.notes


def test_virtual_with_empty_default_pool_and_live_irule_pool_is_not_offline():
    def mutate(parsed):
        empty_pool("/Common/pool-idle")(parsed)
        parsed.virtuals["/Common/vs-idle"].irules.append("/Common/irule-static")

    result = analyze(mutate=mutate)
    assert result.virtual_verdicts["/Common/vs-idle"].verdict != Verdict.OFFLINE_CANDIDATE
    # The empty default pool cannot be detached without touching a virtual
    # server that is alive through its iRule.
    pool_verdict = result.pool_verdicts["/Common/pool-idle"]
    assert pool_verdict.verdict == Verdict.MANUAL_REVIEW
    assert "default pool of virtual server(s) /Common/vs-idle" in pool_verdict.notes


def test_empty_pool_is_skipped_on_standby():
    result = analyze(standby=True, mutate=empty_pool("/Common/pool-idle"))
    assert result.pool_verdicts["/Common/pool-idle"].verdict != Verdict.OFFLINE_CANDIDATE


# ---------------------------------------------------------------------------
# iRules/policies attached to a dead virtual server
# ---------------------------------------------------------------------------


def attach_poolless_irule(virtual_path):
    """A static iRule that answers by itself and names no pool."""

    def mutate(parsed):
        parsed.irules["/Common/irule-redirect"] = IRule(
            full_path="/Common/irule-redirect",
            partition="Common",
            name="irule-redirect",
            definition="when HTTP_REQUEST { HTTP::redirect https://example.net/ }",
        )
        parsed.virtuals[virtual_path].irules.append("/Common/irule-redirect")

    return mutate


def has_review_item(result, object_type, path, caused_by):
    return any(
        item.object_type == object_type and item.full_path == path and item.caused_by == caused_by
        for item in result.manual_review
    )


def test_dead_virtual_with_irule_holds_virtual_and_pool_at_manual_review():
    result = analyze(mutate=attach_poolless_irule("/Common/vs-dead"))
    virtual_verdict = result.virtual_verdicts["/Common/vs-dead"]
    assert virtual_verdict.verdict == Verdict.MANUAL_REVIEW
    assert "/Common/irule-redirect" in virtual_verdict.notes
    assert "can answer traffic without a pool" in virtual_verdict.notes
    pool_verdict = result.pool_verdicts["/Common/pool-dead"]
    assert pool_verdict.verdict == Verdict.MANUAL_REVIEW
    assert "default pool of virtual server(s) /Common/vs-dead" in pool_verdict.notes
    assert "/Common/pool-dead" in result.offline_pools
    assert has_review_item(result, "virtual_server", "/Common/vs-dead", "/Common/irule-redirect")
    assert has_review_item(result, "pool", "/Common/pool-dead", "/Common/vs-dead")
    # Node verdicts never depend on the virtual server.
    assert result.node_verdicts["/Common/node-dead"].verdict == Verdict.OFFLINE_CANDIDATE


def test_dead_virtual_with_policy_holds_virtual_and_pool_at_manual_review():
    def mutate(parsed):
        parsed.policies["/Common/policy-redirect"] = Policy(
            full_path="/Common/policy-redirect", partition="Common", name="policy-redirect"
        )
        parsed.virtuals["/Common/vs-dead"].policies.append("/Common/policy-redirect")

    result = analyze(mutate=mutate)
    virtual_verdict = result.virtual_verdicts["/Common/vs-dead"]
    assert virtual_verdict.verdict == Verdict.MANUAL_REVIEW
    assert "/Common/policy-redirect" in virtual_verdict.notes
    assert result.pool_verdicts["/Common/pool-dead"].verdict == Verdict.MANUAL_REVIEW


def test_empty_pool_virtual_with_irule_holds_both_at_manual_review():
    def mutate(parsed):
        empty_pool("/Common/pool-idle")(parsed)
        attach_poolless_irule("/Common/vs-idle")(parsed)

    result = analyze(mutate=mutate)
    assert result.virtual_verdicts["/Common/vs-idle"].verdict == Verdict.MANUAL_REVIEW
    assert result.pool_verdicts["/Common/pool-idle"].verdict == Verdict.MANUAL_REVIEW


def test_unreadable_irule_on_virtual_holds_its_dead_default_pool():
    def mutate(parsed):
        # Attached but absent from the inventory, as with ltm/rule denied.
        parsed.virtuals["/Common/vs-dead"].irules.append("/Common/irule-unknown")

    result = analyze(mutate=mutate)
    # Pool selection is unprovable: the virtual server is never OFFLINE...
    assert result.virtual_verdicts["/Common/vs-dead"].verdict == Verdict.IN_USE
    # ...and its dead default pool must not be detached from it.
    assert result.pool_verdicts["/Common/pool-dead"].verdict == Verdict.MANUAL_REVIEW


def test_dynamic_irule_on_dead_virtual_holds_pool_once_per_cause():
    def mutate(parsed):
        attach_dynamic_irule(parsed)
        parsed.virtuals["/Common/vs-dead"].irules.append("/Common/irule-dyn")

    result = analyze(mutate=mutate)
    pool_verdict = result.pool_verdicts["/Common/pool-dead"]
    assert pool_verdict.verdict == Verdict.MANUAL_REVIEW
    assert "Dynamic pool-selection iRules are active" in pool_verdict.notes
    assert "default pool of virtual server(s) /Common/vs-dead" in pool_verdict.notes
    items = [item for item in result.manual_review if item.full_path == "/Common/pool-dead"]
    assert len(items) == 2


def test_dead_chain_without_attached_logic_stays_offline():
    # An iRule on another virtual server does not hold this chain.
    result = analyze(mutate=attach_poolless_irule("/Common/vs-web"))
    assert result.virtual_verdicts["/Common/vs-dead"].verdict == Verdict.OFFLINE_CANDIDATE
    assert result.pool_verdicts["/Common/pool-dead"].verdict == Verdict.OFFLINE_CANDIDATE


def test_dead_pool_named_by_irule_is_manual_review():
    def mutate(parsed):
        # pool-irule is named by irule-static on vs-web, never a default pool.
        parsed.pools["/Common/pool-irule"].members = []

    result = analyze(mutate=mutate)
    verdict = result.pool_verdicts["/Common/pool-irule"]
    assert verdict.verdict == Verdict.MANUAL_REVIEW
    assert "Pool has no members" in verdict.notes
    assert "referenced by iRule(s) /Common/irule-static; tmsh refuses the delete" in verdict.notes
    assert "policy(ies)" not in verdict.notes
    assert "/Common/pool-irule" in result.offline_pools
    assert has_review_item(result, "pool", "/Common/pool-irule", "/Common/irule-static")


def test_dead_pool_forwarded_to_by_policy_is_manual_review():
    def mutate(parsed):
        parsed.policies["/Common/policy-forward"] = Policy(
            full_path="/Common/policy-forward",
            partition="Common",
            name="policy-forward",
            forwarded_pools=["/Common/pool-orphan"],
        )

    result = analyze(mutate=mutate)
    # pool-orphan has no members in the fixture: referenced now, so dead
    # rather than ORPHAN, and not removable until the policy is edited.
    verdict = result.pool_verdicts["/Common/pool-orphan"]
    assert verdict.verdict == Verdict.MANUAL_REVIEW
    assert "referenced by policy(ies) /Common/policy-forward" in verdict.notes
    assert "iRule(s)" not in verdict.notes


def test_default_pool_also_named_by_its_virtual_irule_is_held_once_per_cause():
    def mutate(parsed):
        parsed.irules["/Common/irule-dead"] = IRule(
            full_path="/Common/irule-dead",
            partition="Common",
            name="irule-dead",
            definition="pool pool-dead",
            referenced_pools=["/Common/pool-dead"],
        )
        parsed.virtuals["/Common/vs-dead"].irules.append("/Common/irule-dead")

    result = analyze(mutate=mutate)
    verdict = result.pool_verdicts["/Common/pool-dead"]
    assert verdict.verdict == Verdict.MANUAL_REVIEW
    assert "default pool of virtual server(s) /Common/vs-dead" in verdict.notes
    assert "referenced by iRule(s) /Common/irule-dead" in verdict.notes
    items = [item for item in result.manual_review if item.full_path == "/Common/pool-dead"]
    assert len(items) == 2


def test_standby_with_flag_outranks_attached_logic_hold():
    result = analyze(
        standby=True, allow_standby=True, mutate=attach_poolless_irule("/Common/vs-dead")
    )
    assert result.virtual_verdicts["/Common/vs-dead"].verdict == Verdict.UNRELIABLE_STANDBY
    assert result.pool_verdicts["/Common/pool-dead"].verdict == Verdict.UNRELIABLE_STANDBY
