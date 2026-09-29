"""Parsing tests: iRule Tcl analysis, name normalization, stats merge."""

from f5audit.parsing import (
    _parse_arp_map,
    _parse_self_networks,
    analyze_irule_tcl,
    connectivity_note,
    iapp_owner,
    normalize_ref,
    parse_collection,
    parse_monitor_refs,
    split_member_name,
)
from tests.conftest import build_collection, load_fixture

# ---------------------------------------------------------------------------
# iRule Tcl analysis
# ---------------------------------------------------------------------------


def test_irule_static_pool_with_partition():
    refs, dynamic = analyze_irule_tcl("pool /Common/pool-x", "Common")
    assert refs == ["/Common/pool-x"]
    assert dynamic is False


def test_irule_static_pool_implicit_partition():
    refs, dynamic = analyze_irule_tcl("pool pool-x", "PartitionA")
    assert refs == ["/PartitionA/pool-x"]
    assert dynamic is False


def test_irule_dynamic_variable():
    refs, dynamic = analyze_irule_tcl("pool $selected_pool", "Common")
    assert refs == []
    assert dynamic is True


def test_irule_dynamic_class_match_bracket():
    tcl = "pool [class match -value [HTTP::host] equals dg_hosts]"
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == []
    assert dynamic is True


def test_irule_class_match_then_pool_on_later_line():
    tcl = "set target [class match -value [HTTP::host] equals dg_hosts]\npool $target"
    _, dynamic = analyze_irule_tcl(tcl, "Common")
    assert dynamic is True


def test_irule_commented_pool_is_ignored():
    tcl = "# pool old-pool\n   #pool other-pool\npool real-pool"
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == ["/Common/real-pool"]
    assert dynamic is False


def test_irule_nested_tcl_braces():
    tcl = (
        "when HTTP_REQUEST {\n"
        '  if { [HTTP::uri] starts_with "/api" } {\n'
        "    if { [HTTP::header exists X-Env] } { pool /Common/pool-api }\n"
        "  } else {\n"
        "    pool pool-default\n"
        "  }\n"
        "}"
    )
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == ["/Common/pool-api", "/Common/pool-default"]
    assert dynamic is False


def test_irule_namespaced_command_is_not_a_pool_ref():
    refs, dynamic = analyze_irule_tcl("set p [LB::pool something]", "Common")
    assert refs == []


def test_irule_mixed_static_and_dynamic():
    tcl = "pool /Common/pool-a\npool $dynamic"
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == ["/Common/pool-a"]
    assert dynamic is True


def test_irule_pool_in_folder_keeps_full_path():
    refs, dynamic = analyze_irule_tcl("pool /Common/folder/pool-x", "Common")
    assert refs == ["/Common/folder/pool-x"]
    assert dynamic is False


def test_irule_quoted_pool_argument():
    refs, dynamic = analyze_irule_tcl('pool "/Common/pool-x"\npool "pool-y"', "PartitionA")
    assert refs == ["/Common/pool-x", "/PartitionA/pool-y"]
    assert dynamic is False


def test_irule_partition_without_leading_slash():
    refs, _ = analyze_irule_tcl("pool Common/pool-x", "PartitionA")
    assert refs == ["/Common/pool-x"]


def test_irule_pool_word_inside_string_literal_is_not_a_ref():
    tcl = 'log local0. "selected pool for [HTTP::host]"\nHTTP::respond 200 content "pool x"'
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == []
    assert dynamic is False


def test_irule_class_match_with_pool_only_in_string_is_not_dynamic():
    tcl = 'if { [class match [HTTP::uri] starts_with dg] } { log local0. "pool hit" }'
    _, dynamic = analyze_irule_tcl(tcl, "Common")
    assert dynamic is False


def test_irule_class_match_condition_with_literal_pool_is_static():
    # Regression: 'class match' used as an if-condition gates a static
    # 'pool literal'; the selected pool is fully known.
    tcl = (
        "when CLIENT_ACCEPTED {\n"
        " if { [class match [IP::client_addr] equals Office365] } {\n"
        '  log local0. "Client Source IP: [IP::client_addr]"\n'
        "  snat 192.0.2.85\n"
        '  pool "hybrid-Reverse_Proxy-Pool"\n'
        " } \n"
        "}"
    )
    refs, dynamic = analyze_irule_tcl(tcl, "PartitionA")
    assert refs == ["/PartitionA/hybrid-Reverse_Proxy-Pool"]
    assert dynamic is False


def test_irule_class_match_condition_with_unquoted_literal_pool_is_static():
    tcl = "if { [class match [HTTP::host] equals hosts_dg] } { pool /Common/pool-a }"
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == ["/Common/pool-a"]
    assert dynamic is False


def test_irule_class_match_value_assigned_then_used_is_dynamic():
    tcl = "set target [class match -value [HTTP::host] equals dg]\npool $target"
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == []
    assert dynamic is True


def test_irule_quoted_variable_pool_is_dynamic():
    refs, dynamic = analyze_irule_tcl('pool "$selected"\npool "[lindex $pools 0]"', "Common")
    assert refs == []
    assert dynamic is True


def test_irule_class_match_only_without_pool_is_not_dynamic():
    tcl = "if { [class match [IP::client_addr] equals dg] } { snat 192.0.2.44 }"
    refs, dynamic = analyze_irule_tcl(tcl, "Common")
    assert refs == []
    assert dynamic is False


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def test_normalize_ref():
    assert normalize_ref("/Common/x", "Other") == "/Common/x"
    assert normalize_ref("x", "Other") == "/Other/x"
    assert normalize_ref("Common/x", "Other") == "/Common/x"
    assert normalize_ref(None, "Other") == ""


def test_split_member_name_ipv4_and_named():
    assert split_member_name("node1:80") == ("node1", "80")
    assert split_member_name("web.example.com:8443") == ("web.example.com", "8443")


def test_split_member_name_ipv6():
    assert split_member_name("2001:db8::10.443") == ("2001:db8::10", "443")


def test_parse_monitor_refs():
    assert parse_monitor_refs("/Common/http ", "Common") == ["/Common/http"]
    assert parse_monitor_refs("/Common/http and /Common/tcp", "Common") == [
        "/Common/http",
        "/Common/tcp",
    ]
    assert parse_monitor_refs("min 1 of { /Common/a /Common/b }", "Common") == [
        "/Common/a",
        "/Common/b",
    ]
    assert parse_monitor_refs("default", "Common") == []
    assert parse_monitor_refs("custom_mon", "PartA") == ["/PartA/custom_mon"]


# ---------------------------------------------------------------------------
# Full collection parsing (fixtures)
# ---------------------------------------------------------------------------


def test_parse_collection_builds_models():
    parsed = parse_collection(build_collection())

    assert parsed.system.hostname == "bigip1.example.net"
    assert parsed.system.version == "15.1.10"
    assert parsed.system.failover_state == "active"
    assert parsed.system.partitions_collected == ["Common"]

    node = parsed.nodes["/Common/node-web-1"]
    assert node.address == "10.0.0.1"
    assert node.total_conns == 500

    pool = parsed.pools["/Common/pool-web"]
    assert pool.monitors == ["/Common/mon-used"]
    assert len(pool.members) == 1
    member = pool.members[0]
    assert member.node_full_path == "/Common/node-web-1"
    assert member.port == "80"
    assert member.total_conns == 450

    virtual = parsed.virtuals["/Common/vs-web"]
    assert virtual.destination == "192.0.2.10:443"
    assert virtual.default_pool == "/Common/pool-web"
    assert virtual.total_conns == 12345
    assert virtual.admin_state == "enabled"
    assert parsed.virtuals["/Common/vs-disabled"].admin_state == "disabled"

    irule = parsed.irules["/Common/irule-static"]
    assert irule.referenced_pools == ["/Common/pool-irule"]
    assert irule.has_dynamic_pool_selection is False

    assert parsed.monitors["/Common/mon-orphan"].type == "http"


def test_parse_collection_standby_state():
    parsed = parse_collection(build_collection(standby=True))
    assert parsed.system.failover_state == "standby"


# ---------------------------------------------------------------------------
# Network context (ARP table + self-IP subnets)
# ---------------------------------------------------------------------------


class _FakeData:
    """Duck-typed CollectionData for the pure network parsers."""

    def __init__(self, datasets):
        self.datasets = datasets

    def get(self, key, default=None):
        return self.datasets.get(key, default)


def test_parse_arp_map_merges_dynamic_and_static_entries():
    arp_map = _parse_arp_map(
        _FakeData(
            {
                "net_arp_stats": load_fixture("net_arp_stats.json"),
                "net_arp": load_fixture("net_arp.json"),
            }
        )
    )
    assert arp_map["10.0.0.1"] == "00:00:5e:00:53:01"  # dynamic, resolved
    assert arp_map["10.0.0.62"] == "00:00:5e:00:53:62"  # static entry
    assert "10.0.0.33" not in arp_map  # incomplete entry is not presence


def test_parse_arp_map_skips_entries_without_address():
    raw = {
        "entries": {
            "https://localhost/mgmt/tm/net/arp/x/stats": {
                "nestedStats": {"entries": {"macAddress": {"description": "00:00:5e:00:53:99"}}}
            }
        }
    }
    assert _parse_arp_map(_FakeData({"net_arp_stats": raw, "net_arp": None})) == {}


def test_parse_self_networks_handles_route_domains_and_malformed():
    data = _FakeData(
        {
            "net_self": [
                {"address": "10.0.0.5/26"},
                {"address": "10.9.0.5%2/24"},
                {"address": "not-an-ip/24"},
                {"address": "10.9.9.9"},
            ]
        }
    )
    networks = _parse_self_networks(data)
    assert [(rd, str(net)) for rd, net in networks] == [
        ("0", "10.0.0.0/26"),
        ("2", "10.9.0.0/24"),
    ]


def test_connectivity_note_classifications():
    arp_map = {"10.0.0.1": "00:00:5e:00:53:01", "10.9.0.7%2": "00:00:5e:00:53:07"}
    self_networks = _parse_self_networks(
        _FakeData({"net_self": [{"address": "10.0.0.5/26"}, {"address": "10.9.0.5%2/24"}]})
    )

    mac, note = connectivity_note("10.0.0.1", arp_map, self_networks, True)
    assert mac == "00:00:5e:00:53:01"
    assert note == "in ARP table (MAC 00:00:5e:00:53:01)"

    # Route-domain address matched by its exact configured string.
    mac, note = connectivity_note("10.9.0.7%2", arp_map, self_networks, True)
    assert mac == "00:00:5e:00:53:07"

    # '%0' suffix falls back to the bare-IP ARP entry.
    mac, _ = connectivity_note("10.0.0.1%0", arp_map, self_networks, True)
    assert mac == "00:00:5e:00:53:01"

    assert connectivity_note("10.0.0.50", arp_map, self_networks, True) == (
        "",
        "on local subnet, no ARP entry (idle or down)",
    )
    # Same IP range, different route domain: not the same L2 segment.
    assert connectivity_note("10.0.0.50%2", arp_map, self_networks, True) == (
        "",
        "not directly connected (behind a router)",
    )
    assert connectivity_note("10.0.0.99", arp_map, self_networks, True) == (
        "",
        "not directly connected (behind a router)",
    )
    assert connectivity_note("10.0.0.50", arp_map, self_networks, False) == (
        "",
        "self-IP data unavailable; connectivity not classified",
    )
    assert connectivity_note("app.example.net", arp_map, self_networks, True) == (
        "",
        "FQDN node (no IP to check)",
    )
    assert connectivity_note("2001:db8::10", arp_map, self_networks, True) == (
        "",
        "IPv6 address (not analyzed)",
    )


def test_parse_collection_builds_network_info():
    parsed = parse_collection(build_collection())
    assert parsed.network_collected is True
    info = parsed.network["10.0.0.1"]
    assert info.arp_mac == "00:00:5e:00:53:01"
    assert info.connectivity == "in ARP table (MAC 00:00:5e:00:53:01)"
    # /26 self-IP: 10.0.0.50 is local, 10.0.0.99 is routed.
    local_note = parsed.network["10.0.0.50"].connectivity
    assert local_note == "on local subnet, no ARP entry (idle or down)"
    assert parsed.network["10.0.0.99"].connectivity == "not directly connected (behind a router)"


def test_parse_collection_without_network_datasets():
    parsed = parse_collection(build_collection(network=False))
    assert parsed.network_collected is False
    assert parsed.network == {}


# ---------------------------------------------------------------------------
# iApp ownership
# ---------------------------------------------------------------------------


def test_iapp_owner_prefers_app_service_attribute():
    item = {"appService": "/Windows/adfs.app/adfs"}
    assert iapp_owner(item, "/Windows/10.0.0.10:443") == "/Windows/adfs.app/adfs"


def test_iapp_owner_falls_back_to_app_folder():
    path = (
        "/Windows/Login.example.local_ADFS_Proxy.app/Login.example.local_ADFS_Proxy_adfs_pool_443"
    )
    assert iapp_owner({}, path) == "/Windows/Login.example.local_ADFS_Proxy.app"


def test_iapp_owner_ignores_app_in_object_names():
    assert iapp_owner({}, "/Common/portal.app01") == ""
    assert iapp_owner({}, "/Common/api.app.example.net") == ""
    assert iapp_owner({}, "/Common/pool.app") == ""  # last segment is the object
    assert iapp_owner({}, "/Common/pool-web") == ""


def test_parse_collection_reads_app_service():
    data = build_collection()
    data.datasets["ltm_pool_members@/Common/pool-dead"][0]["appService"] = "/Common/x.app/x"
    parsed = parse_collection(data)
    member = parsed.pools["/Common/pool-dead"].members[0]
    assert member.app_service == "/Common/x.app/x"
    assert parsed.pools["/Common/pool-web"].app_service == ""
    assert parsed.nodes["/Common/node-dead"].app_service == ""


def test_virtual_rollback_fields_and_profiles_are_parsed():
    parsed = parse_collection(build_collection())
    virtual = parsed.virtuals["/Common/vs-dead"]
    assert virtual.destination == "192.0.2.13:443"
    assert virtual.destination_path == "/Common/192.0.2.13:443"
    assert virtual.mask == "255.255.255.255"
    assert virtual.ip_protocol == "tcp"
    assert virtual.snat_type == "snat"
    assert virtual.snat_pool == "/Common/snat-example"
    assert virtual.vlans == ["/Common/vlan-external"]
    assert virtual.vlans_enabled
    assert virtual.fallback_persistence == "/Common/source_addr"
    assert virtual.profiles_collected
    assert [(p.full_path, p.context) for p in virtual.profiles] == [
        ("/Common/tcp", "all"),
        ("/Common/http", "all"),
        ("/Common/clientssl-example", "clientside"),
    ]
    # No profiles dataset (older raw cache): unknown, not "no profiles".
    assert not parsed.virtuals["/Common/vs-web"].profiles_collected


def test_pool_rollback_fields_are_parsed():
    collection = build_collection()
    collection.datasets["ltm_pool@Common"][0].update(
        {
            "monitor": "min 1 of { /Common/http /Common/tcp } ",
            "minActiveMembers": 1,
            "slowRampTime": 30,
            "description": "web tier",
        }
    )
    collection.datasets["ltm_pool_members@/Common/pool-web"][0].update(
        {"ratio": 3, "connectionLimit": 100}
    )
    pool = parse_collection(collection).pools["/Common/pool-web"]
    assert pool.monitor_expression == "min 1 of { /Common/http /Common/tcp }"
    assert pool.min_active_members == 1
    assert pool.slow_ramp_time == 30
    assert pool.description == "web tier"
    assert pool.members[0].ratio == 3
    assert pool.members[0].connection_limit == 100
