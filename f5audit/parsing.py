"""Turn raw iControl REST JSON into the f5audit data model.

Includes the iRule Tcl analysis (static pool references vs dynamic pool
selection) and the flattening of BIG-IP stats documents.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from .collector import CollectionData
from .models import (
    IRule,
    Monitor,
    Node,
    NodeNetworkInfo,
    Policy,
    Pool,
    PoolMember,
    SystemInfo,
    VirtualServer,
)

logger = logging.getLogger("f5audit.parsing")

# --- iRule analysis -------------------------------------------------------

COMMENT_LINE_RE = re.compile(r"^\s*#")
# Static reference: 'pool /Common/x', 'pool x', 'pool "x"' or a folder path
# such as 'pool /Common/folder/x'. The lookbehind avoids matching Tcl
# namespaced commands such as 'LB::pool'.
STATIC_POOL_RE = re.compile(r'(?<!:)\bpool\s+"?(/?[\w.-]+(?:/[\w.-]+)*)"?')
# 'pool "x"' is a real reference; any other quoted string on the line is
# free text (log messages, headers) and must not yield pool references.
_QUOTED_POOL_ARG_RE = re.compile(r'(?<!:)(\bpool\s+)"([^"]*)"')
_STRING_LITERAL_RE = re.compile(r'"[^"]*"')
# Dynamic selection that cannot be resolved statically: 'pool $var',
# 'pool [expr ...]' / 'pool [class match -value ...]'. A datagroup lookup
# is only dynamic when its value reaches the pool command this way; a
# 'class match' used as an if-condition followed by 'pool literal' is a
# static reference, not a dynamic one.
DYNAMIC_POOL_RE = re.compile(r"(?<!:)\bpool\s+[\[$]")

# Monitor strings look like '/Common/http', '/Common/http and /Common/tcp',
# or 'min 1 of { /Common/http /Common/tcp }'.
_MONITOR_TOKEN_SPLIT_RE = re.compile(r"[\s{}]+")
_MONITOR_KEYWORDS = {"and", "min", "of", "none", "default", ""}


def normalize_ref(name: str | None, default_partition: str) -> str:
    """Normalize an object reference to the full '/Partition/name' form."""
    if not name:
        return ""
    name = name.strip()
    if name.startswith("/"):
        return name
    if "/" in name:
        return "/" + name
    return f"/{default_partition}/{name}"


def split_member_name(member_name: str) -> tuple[str, str]:
    """Split a pool member name ('node:port', IPv6 uses 'addr.port')."""
    if member_name.count(":") > 1:
        # IPv6 address: the port separator is a dot.
        node, _, port = member_name.rpartition(".")
        if node:
            return node, port
        return member_name, ""
    node, _, port = member_name.rpartition(":")
    if node:
        return node, port
    return member_name, ""


def parse_monitor_refs(value: str | None, default_partition: str) -> list[str]:
    """Extract normalized monitor full paths from a raw monitor string."""
    if not value:
        return []
    refs = []
    for token in _MONITOR_TOKEN_SPLIT_RE.split(value):
        if token.lower() in _MONITOR_KEYWORDS or token.isdigit():
            continue
        refs.append(normalize_ref(token, default_partition))
    return refs


def _strip_string_literals(line: str) -> str:
    """Unquote a 'pool "x"' argument and blank every other string literal."""
    line = _QUOTED_POOL_ARG_RE.sub(r"\1\2", line)
    return _STRING_LITERAL_RE.sub('""', line)


def analyze_irule_tcl(definition: str, partition: str) -> tuple[list[str], bool]:
    """Return (static_pool_refs, has_dynamic_pool_selection) for Tcl code.

    Commented lines are ignored. A pool command is dynamic when its
    argument is a variable or a command substitution; every other pool
    command is a static reference to a literal name.
    """
    static_refs: list[str] = []
    dynamic = False
    for line in (definition or "").splitlines():
        if COMMENT_LINE_RE.match(line):
            continue
        # Unquote first so that 'pool "$var"' is seen as dynamic too.
        line = _strip_string_literals(line)
        if DYNAMIC_POOL_RE.search(line):
            dynamic = True
        for match in STATIC_POOL_RE.finditer(line):
            ref = normalize_ref(match.group(1), partition)
            if ref and ref not in static_refs:
                static_refs.append(ref)
    return static_refs, dynamic


# --- Stats flattening -----------------------------------------------------


def stat_value(entries: dict[str, Any], key: str, default: Any = None) -> Any:
    entry = entries.get(key)
    if not isinstance(entry, dict):
        return default
    if "value" in entry:
        return entry["value"]
    return entry.get("description", default)


def flatten_stats(raw: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Map an F5 stats document to {object_full_path: stat_entries}."""
    result: dict[str, dict[str, Any]] = {}
    for url, wrapper in ((raw or {}).get("entries") or {}).items():
        entries = (wrapper.get("nestedStats") or {}).get("entries") or {}
        full_path = stat_value(entries, "tmName")
        if not full_path:
            # Derive from the URL: .../~Common~obj/stats -> /Common/obj
            segment = url.rsplit("/stats", 1)[0].rsplit("/", 1)[-1]
            full_path = segment.replace("~", "/")
        result[full_path] = entries
    return result


# --- Network context (ARP table + self-IP subnets) ------------------------


def iter_stats_entries(raw: dict[str, Any] | None):
    """Yield each nestedStats entries dict of an F5 stats document.

    Unlike flatten_stats, no keying is attempted: dynamic ARP entries
    carry no tmName and are keyed by IP-ish URL fragments.
    """
    for wrapper in ((raw or {}).get("entries") or {}).values():
        entries = (wrapper.get("nestedStats") or {}).get("entries") or {}
        if entries:
            yield entries


# An unresolved ARP entry is not evidence that the host exists.
_ARP_ABSENT_STATUSES = {"incomplete", "down", "unresolved"}


def _split_route_domain(address: str) -> tuple[str, str]:
    """'10.0.0.1%2' -> ('10.0.0.1', '2'); no suffix means route domain 0."""
    ip_part, _, route_domain = address.partition("%")
    return ip_part, route_domain or "0"


def _parse_arp_map(data: CollectionData) -> dict[str, str]:
    """Map address -> MAC from the dynamic ARP stats plus static entries.

    Dynamic ARP stats entries use the same field names as the static
    net/arp collection (ipAddress, macAddress, status, vlan, tmName,
    expireInSec); entries without an address are skipped rather than
    trusted.
    """
    arp_map: dict[str, str] = {}
    for entries in iter_stats_entries(data.get("net_arp_stats")):
        address = stat_value(entries, "ipAddress")
        status = str(stat_value(entries, "status", "") or "").lower()
        if not address or status in _ARP_ABSENT_STATUSES:
            continue
        arp_map[str(address)] = str(stat_value(entries, "macAddress", "") or "")
    for item in data.get("net_arp") or []:
        address = item.get("ipAddress")
        if address and address not in arp_map:
            arp_map[address] = item.get("macAddress", "")
    return arp_map


def _parse_self_networks(data: CollectionData) -> list[tuple[str, Any]]:
    """[(route_domain, ip_network)] from self-IPs ('10.0.0.5%2/24')."""
    networks: list[tuple[str, Any]] = []
    for item in data.get("net_self") or []:
        address = item.get("address", "")
        if "/" not in address:
            continue
        ip_part, _, prefix = address.rpartition("/")
        ip_part, route_domain = _split_route_domain(ip_part)
        try:
            network = ipaddress.ip_interface(f"{ip_part}/{prefix}").network
        except ValueError:
            logger.debug("Skipping malformed self-IP address: %s", address)
            continue
        networks.append((route_domain, network))
    return networks


def connectivity_note(
    address: str,
    arp_map: dict[str, str],
    self_networks: list[tuple[str, Any]],
    self_data_present: bool,
) -> tuple[str, str]:
    """Classify one node address: (arp_mac, human-readable note).

    Informational only — ARP absence means "not seen at collection
    time", never "gone", so this feeds report columns, not verdicts.
    """
    ip_part, route_domain = _split_route_domain(address)
    mac = arp_map.get(address)
    if mac is None and route_domain == "0":
        mac = arp_map.get(ip_part)
    if mac:
        return mac, f"in ARP table (MAC {mac})"
    try:
        node_ip = ipaddress.ip_address(ip_part)
    except ValueError:
        return "", "FQDN node (no IP to check)"
    if node_ip.version == 6:
        return "", "IPv6 address (not analyzed)"
    if not self_data_present:
        return "", "self-IP data unavailable; connectivity not classified"
    for self_route_domain, network in self_networks:
        if self_route_domain == route_domain and node_ip in network:
            return "", "on local subnet, no ARP entry (idle or down)"
    return "", "not directly connected (behind a router)"


# --- Parsed aggregate -----------------------------------------------------


@dataclass
class ParsedData:
    system: SystemInfo = field(default_factory=SystemInfo)
    nodes: dict[str, Node] = field(default_factory=dict)
    pools: dict[str, Pool] = field(default_factory=dict)
    virtuals: dict[str, VirtualServer] = field(default_factory=dict)
    irules: dict[str, IRule] = field(default_factory=dict)
    policies: dict[str, Policy] = field(default_factory=dict)
    monitors: dict[str, Monitor] = field(default_factory=dict)
    network: dict[str, NodeNetworkInfo] = field(default_factory=dict)  # keyed by node address
    network_collected: bool = False  # False => raw cache without net_* datasets


def _iter_partition_items(data: CollectionData, prefix: str):
    for key in data.keys_with_prefix(prefix + "@"):
        partition = key.split("@", 1)[1]
        for item in data.get(key) or []:
            yield partition, item


def _full_path(item: dict[str, Any], partition: str) -> str:
    return item.get("fullPath") or f"/{item.get('partition', partition)}/{item.get('name', '')}"


def iapp_owner(item: dict[str, Any], full_path: str) -> str:
    """The iApp that owns an object, or '' when none.

    BIG-IP sets 'appService' on every iApp-owned object; the '<name>.app'
    folder an iApp always deploys into is the fallback. The folder is
    matched per path segment (never the last one), so a node named
    'portal.app01' or 'api.app.example.net' is not mistaken for an iApp.
    """
    app_service = item.get("appService")
    if app_service:
        return str(app_service)
    segments = full_path.strip("/").split("/")
    for index, segment in enumerate(segments[:-1]):
        if segment.endswith(".app"):
            return "/" + "/".join(segments[: index + 1])
    return ""


def parse_collection(data: CollectionData) -> ParsedData:
    parsed = ParsedData()
    parsed.system = _parse_system(data)
    _parse_nodes(data, parsed)
    _parse_pools(data, parsed)
    _parse_virtuals(data, parsed)
    _parse_irules(data, parsed)
    _parse_policies(data, parsed)
    _parse_monitors(data, parsed)
    _parse_network(data, parsed)
    return parsed


def _parse_system(data: CollectionData) -> SystemInfo:
    info = SystemInfo()
    info.collection_timestamp = data.meta.get("collected_at", "")

    version_raw = data.get("sys_version") or {}
    for wrapper in (version_raw.get("entries") or {}).values():
        entries = (wrapper.get("nestedStats") or {}).get("entries") or {}
        info.version = stat_value(entries, "Version", info.version) or ""

    failover_raw = data.get("sys_failover") or {}
    failover_text = ""
    api_raw = failover_raw.get("apiRawValues") or {}
    failover_text = api_raw.get("apiAnonymous", "") or ""
    if not failover_text and "entries" in failover_raw:
        for wrapper in failover_raw["entries"].values():
            entries = (wrapper.get("nestedStats") or {}).get("entries") or {}
            failover_text = str(stat_value(entries, "status", "") or "")
    lowered = failover_text.lower()
    if "standby" in lowered:
        info.failover_state = "standby"
    elif "active" in lowered:
        info.failover_state = "active"
    # Best-effort uptime proxy: 'Failover active for 32d 05:12:33'
    match = re.search(r"for\s+(.+)", failover_text)
    if match:
        info.uptime = f"time in current failover state: {match.group(1).strip()}"

    for device in data.get("cm_device") or []:
        if device.get("selfDevice") in ("true", True):
            info.hostname = device.get("hostname", info.hostname)
            if not info.failover_state:
                info.failover_state = device.get("failoverState", "")
            if not info.version:
                info.version = device.get("version", "")
        if device.get("failoverState") == "active":
            info.active_device = device.get("hostname", "")
    if not info.failover_state:
        info.failover_state = "unknown"

    info.partitions_collected = [
        item.get("name", "") for item in (data.get("auth_partition") or [])
    ]
    denied = data.meta.get("denied") or []
    info.partitions_denied = sorted(
        {entry.get("partition") for entry in denied if entry.get("partition")}
    )
    info.missing_endpoints = sorted(
        set(data.meta.get("missing_endpoints") or [])
        | {entry.get("endpoint", "") for entry in denied}
    )
    info.resumed_at = list(data.meta.get("resumed_at") or [])
    return info


def _parse_nodes(data: CollectionData, parsed: ParsedData) -> None:
    stats = flatten_stats(data.get("ltm_node_stats"))
    for partition, item in _iter_partition_items(data, "ltm_node"):
        full_path = _full_path(item, partition)
        node = Node(
            full_path=full_path,
            partition=item.get("partition", partition),
            name=item.get("name", ""),
            address=item.get("address", item.get("fqdn", {}).get("tmName", "")),
            monitor=(item.get("monitor") or "").strip(),
            admin_state=item.get("session", ""),
            app_service=iapp_owner(item, full_path),
        )
        entries = stats.get(full_path)
        if entries:
            node.total_conns = stat_value(entries, "serverside.totConns")
            node.availability = stat_value(entries, "status.availabilityState", "") or ""
            node.monitor_status = stat_value(entries, "monitorStatus", "") or ""
        parsed.nodes[full_path] = node


def _parse_network(data: CollectionData, parsed: ParsedData) -> None:
    parsed.network_collected = any(
        data.get(key) is not None for key in ("net_arp_stats", "net_self", "net_arp")
    )
    if not parsed.network_collected:
        return
    arp_map = _parse_arp_map(data)
    self_networks = _parse_self_networks(data)
    self_data_present = data.get("net_self") is not None
    for node in parsed.nodes.values():
        if not node.address or node.address in parsed.network:
            continue
        mac, note = connectivity_note(node.address, arp_map, self_networks, self_data_present)
        parsed.network[node.address] = NodeNetworkInfo(
            address=node.address, arp_mac=mac, connectivity=note
        )


def _parse_pool_member(
    item: dict[str, Any], pool_partition: str, member_stats: dict[str, dict[str, Any]]
) -> PoolMember:
    partition = item.get("partition", pool_partition)
    node_name, port = split_member_name(item.get("name", ""))
    node_full_path = normalize_ref(node_name, partition)
    member = PoolMember(
        node_full_path=node_full_path,
        port=port,
        partition=partition,
        admin_state=item.get("session", ""),
        availability=item.get("state", ""),
        priority_group=item.get("priorityGroup", 0),
        app_service=iapp_owner(item, item.get("fullPath", "")),
    )
    entries = member_stats.get(f"{node_full_path}:{port}") or member_stats.get(
        item.get("fullPath", "")
    )
    if entries:
        member.cur_conns = stat_value(entries, "serverside.curConns")
        member.total_conns = stat_value(entries, "serverside.totConns")
        availability = stat_value(entries, "status.availabilityState")
        if availability:
            member.availability = availability
    return member


def _parse_pools(data: CollectionData, parsed: ParsedData) -> None:
    pool_stats = flatten_stats(data.get("ltm_pool_stats"))
    for partition, item in _iter_partition_items(data, "ltm_pool"):
        full_path = _full_path(item, partition)
        pool = Pool(
            full_path=full_path,
            partition=item.get("partition", partition),
            name=item.get("name", ""),
            monitors=parse_monitor_refs(item.get("monitor"), partition),
            lb_method=item.get("loadBalancingMode", ""),
            app_service=iapp_owner(item, full_path),
        )
        entries = pool_stats.get(full_path)
        if entries:
            pool.availability = stat_value(entries, "status.availabilityState", "") or ""
            pool.total_conns = stat_value(entries, "serverside.totConns")
        member_stats = flatten_stats(data.get(f"ltm_pool_member_stats@{full_path}"))
        for member_item in data.get(f"ltm_pool_members@{full_path}") or []:
            pool.members.append(_parse_pool_member(member_item, pool.partition, member_stats))
        parsed.pools[full_path] = pool


def _parse_virtuals(data: CollectionData, parsed: ParsedData) -> None:
    stats = flatten_stats(data.get("ltm_virtual_stats"))
    for partition, item in _iter_partition_items(data, "ltm_virtual"):
        full_path = _full_path(item, partition)
        vs_partition = item.get("partition", partition)
        destination = item.get("destination", "")
        # Destination comes as '/Common/10.0.0.1:443'; keep only ip:port.
        destination = destination.rsplit("/", 1)[-1]
        virtual = VirtualServer(
            full_path=full_path,
            partition=vs_partition,
            name=item.get("name", ""),
            destination=destination,
            default_pool=normalize_ref(item.get("pool"), vs_partition),
            irules=[normalize_ref(r, vs_partition) for r in item.get("rules") or []],
            persistence=[
                normalize_ref(p.get("name"), p.get("partition", vs_partition))
                for p in item.get("persist") or []
            ],
            admin_state="disabled" if item.get("disabled") else "enabled",
            app_service=iapp_owner(item, full_path),
        )
        for policy_item in data.get(f"ltm_virtual_policies@{full_path}") or []:
            virtual.policies.append(_full_path(policy_item, vs_partition))
        entries = stats.get(full_path)
        if entries:
            virtual.total_conns = stat_value(entries, "clientside.totConns")
            virtual.bits_in = stat_value(entries, "clientside.bitsIn")
            virtual.bits_out = stat_value(entries, "clientside.bitsOut")
            virtual.availability = stat_value(entries, "status.availabilityState", "") or ""
            enabled_state = stat_value(entries, "status.enabledState")
            if enabled_state:
                virtual.admin_state = enabled_state
        parsed.virtuals[full_path] = virtual


def _parse_irules(data: CollectionData, parsed: ParsedData) -> None:
    for partition, item in _iter_partition_items(data, "ltm_rule"):
        full_path = _full_path(item, partition)
        rule_partition = item.get("partition", partition)
        definition = item.get("apiAnonymous", "")
        referenced_pools, dynamic = analyze_irule_tcl(definition, rule_partition)
        parsed.irules[full_path] = IRule(
            full_path=full_path,
            partition=rule_partition,
            name=item.get("name", ""),
            definition=definition,
            referenced_pools=referenced_pools,
            has_dynamic_pool_selection=dynamic,
        )


def _parse_policies(data: CollectionData, parsed: ParsedData) -> None:
    for partition, item in _iter_partition_items(data, "ltm_policy"):
        full_path = _full_path(item, partition)
        policy_partition = item.get("partition", partition)
        policy = Policy(
            full_path=full_path,
            partition=policy_partition,
            name=item.get("name", ""),
        )
        for rule in data.get(f"ltm_policy_rules@{full_path}") or []:
            actions = (rule.get("actionsReference") or {}).get("items") or []
            for action in actions:
                pool_ref = action.get("pool")
                if pool_ref:
                    ref = normalize_ref(pool_ref, policy_partition)
                    if ref not in policy.forwarded_pools:
                        policy.forwarded_pools.append(ref)
        parsed.policies[full_path] = policy

    # Attach virtuals to policies (built from the VS side).
    for virtual in parsed.virtuals.values():
        for policy_path in virtual.policies:
            policy = parsed.policies.get(policy_path)
            if policy and virtual.full_path not in policy.attached_virtuals:
                policy.attached_virtuals.append(virtual.full_path)


def _parse_monitors(data: CollectionData, parsed: ParsedData) -> None:
    for key in data.keys_with_prefix("ltm_monitor_"):
        type_and_partition = key[len("ltm_monitor_") :]
        monitor_type, _, partition = type_and_partition.partition("@")
        for item in data.get(key) or []:
            full_path = _full_path(item, partition)
            parsed.monitors[full_path] = Monitor(
                full_path=full_path,
                partition=item.get("partition", partition),
                name=item.get("name", ""),
                type=monitor_type,
            )
