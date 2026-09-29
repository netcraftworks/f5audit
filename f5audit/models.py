"""Data model for f5audit.

Plain stdlib dataclasses (no pydantic) to keep the dependency footprint
minimal on the target VDI machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Node:
    full_path: str
    partition: str
    name: str
    address: str = ""  # IP or FQDN
    monitor: str = ""  # raw monitor string as configured ("default", "/Common/icmp", ...)
    admin_state: str = ""  # enabled / disabled / forced offline
    monitor_status: str = ""
    availability: str = ""
    total_conns: int | None = None
    app_service: str = ""  # owning iApp, empty if none


@dataclass
class NodeNetworkInfo:
    """L2/L3 context for one node address (informational, never a verdict)."""

    address: str
    arp_mac: str = ""
    connectivity: str = ""  # human-readable note for the report


@dataclass
class PoolMember:
    node_full_path: str
    port: str
    partition: str = ""
    admin_state: str = ""
    availability: str = ""
    cur_conns: int | None = None
    total_conns: int | None = None
    priority_group: int = 0
    app_service: str = ""


@dataclass
class Pool:
    full_path: str
    partition: str
    name: str
    monitors: list[str] = field(default_factory=list)  # normalized full paths
    lb_method: str = ""
    members: list[PoolMember] = field(default_factory=list)
    availability: str = ""
    total_conns: int | None = None
    app_service: str = ""


@dataclass
class VirtualServer:
    full_path: str
    partition: str
    name: str
    destination: str = ""  # ip:port
    default_pool: str = ""  # normalized full path, empty if none
    irules: list[str] = field(default_factory=list)
    policies: list[str] = field(default_factory=list)
    profiles: list[str] = field(default_factory=list)
    persistence: list[str] = field(default_factory=list)
    admin_state: str = ""  # enabled / disabled
    availability: str = ""
    total_conns: int | None = None
    bits_in: int | None = None
    bits_out: int | None = None
    app_service: str = ""


@dataclass
class IRule:
    full_path: str
    partition: str
    name: str
    definition: str = ""  # raw Tcl (apiAnonymous)
    referenced_pools: list[str] = field(default_factory=list)  # static refs, normalized
    has_dynamic_pool_selection: bool = False


@dataclass
class Policy:
    full_path: str
    partition: str
    name: str
    forwarded_pools: list[str] = field(default_factory=list)  # normalized full paths
    attached_virtuals: list[str] = field(default_factory=list)


@dataclass
class Monitor:
    full_path: str
    partition: str
    name: str
    type: str = ""


@dataclass
class SystemInfo:
    hostname: str = ""
    version: str = ""
    failover_state: str = ""  # active / standby / unknown
    active_device: str = ""
    uptime: str = ""  # human readable, best effort
    collection_timestamp: str = ""
    partitions_collected: list[str] = field(default_factory=list)
    partitions_denied: list[str] = field(default_factory=list)
    missing_endpoints: list[str] = field(default_factory=list)
    resumed_at: list[str] = field(default_factory=list)  # resumed-collection timestamps
