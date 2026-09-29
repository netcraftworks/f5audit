"""tmsh command text for the report's change-request and rollback columns.

Every string built here is informational text for the human writing the
change request; f5audit never executes anything. Pure functions over the
data model, so the report only decides *which* commands a row gets.

Syntax follows the official tmsh reference (clouddocs.f5.com,
tmsh-reference: ltm node, ltm pool, ltm virtual, ltm virtual-address):

- `delete ltm pool` is refused while anything references the pool: a
  virtual server's default pool, an LTM policy forward action, or an iRule
  naming it literally. `pool $var` in an iRule is not validated.
- `modify ltm virtual <vs> pool none` detaches a default pool; it does not
  touch iRule or policy references.
- Deleting the last virtual server on an address also deletes the
  virtual-address (auto-delete defaults to true); re-creating the virtual
  server re-creates it with default settings.
- `create ltm pool ... members add { ... }` auto-creates missing nodes with
  default settings, which is why rollback re-creates nodes first.
- Safe order: virtual servers -> pool -> nodes; rollback is the reverse.

Unconfirmed in the official reference: the '.' port separator for IPv6
pool members (it is documented for virtual destinations only).
"""

from __future__ import annotations

import ipaddress

from .models import Node, Pool, PoolMember, VirtualServer

ANY_SOURCE = {"", "0.0.0.0/0", "::/0"}


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def member_ref(node_path: str, port: str) -> str:
    # F5 quirk: a node named by its IPv6 literal separates the port with '.'.
    node_name = node_path.rsplit("/", 1)[-1]
    separator = "." if node_name.count(":") > 1 else ":"
    return f"{node_path}{separator}{port}"


def delete_node_command(node_path: str) -> str:
    return f"delete ltm node {node_path}"


def delete_pool_command(pool_path: str) -> str:
    return f"delete ltm pool {pool_path}"


def delete_virtual_command(virtual_path: str) -> str:
    return f"delete ltm virtual {virtual_path}"


def node_create_command(node: Node) -> str:
    ip_part = node.address.partition("%")[0]
    try:
        ipaddress.ip_address(ip_part)
        target = f"address {node.address}"
    except ValueError:
        target = f"fqdn {{ name {node.address} }}"
    command = f"create ltm node {node.full_path} {target}"
    # The node-level monitor lives on the node object and is lost with it;
    # the pool monitor survives on the pool and needs no rollback.
    if node.monitor and node.monitor != "default":
        command += f" monitor {node.monitor}"
    return command


def _member_spec(member: PoolMember) -> str:
    options = []
    if member.priority_group:
        options.append(f"priority-group {member.priority_group}")
    if member.ratio and member.ratio != 1:
        options.append(f"ratio {member.ratio}")
    if member.connection_limit:
        options.append(f"connection-limit {member.connection_limit}")
    if member.admin_state == "user-disabled":
        options.append("session user-disabled")
    reference = member_ref(member.node_full_path, member.port)
    return f"{reference} {{ {' '.join(options)} }}" if options else reference


def remove_member_command(pool_path: str, member: PoolMember) -> str:
    reference = member_ref(member.node_full_path, member.port)
    return f"modify ltm pool {pool_path} members delete {{ {reference} }}"


def add_member_command(pool_path: str, member: PoolMember) -> str:
    return f"modify ltm pool {pool_path} members add {{ {_member_spec(member)} }}"


def pool_create_command(pool: Pool) -> str:
    """Re-create a pool with its members and non-default settings."""
    parts = [f"create ltm pool {pool.full_path}"]
    if pool.members:
        specs = " ".join(_member_spec(member) for member in pool.members)
        parts.append(f"members add {{ {specs} }}")
    if pool.monitor_expression:
        parts.append(f"monitor {pool.monitor_expression}")
    if pool.lb_method and pool.lb_method != "round-robin":
        parts.append(f"load-balancing-mode {pool.lb_method}")
    if pool.min_active_members:
        parts.append(f"min-active-members {pool.min_active_members}")
    if pool.slow_ramp_time != 10:
        parts.append(f"slow-ramp-time {pool.slow_ramp_time}")
    if pool.service_down_action not in ("", "none"):
        parts.append(f"service-down-action {pool.service_down_action}")
    if pool.description:
        parts.append(f"description {_quote(pool.description)}")
    return " ".join(parts)


def detach_pool_command(virtual_path: str) -> str:
    return f"modify ltm virtual {virtual_path} pool none"


def reattach_pool_command(virtual_path: str, pool_path: str) -> str:
    return f"modify ltm virtual {virtual_path} pool {pool_path}"


def virtual_create_command(virtual: VirtualServer) -> str:
    """Re-create a virtual server; empty when its profiles were never
    collected, because a virtual rebuilt without its profiles (tcp, http,
    clientssl...) is not a rollback."""
    if not virtual.profiles_collected:
        return ""
    destination = virtual.destination_path or virtual.destination
    parts = [f"create ltm virtual {virtual.full_path} destination {destination}"]
    if virtual.mask:
        parts.append(f"mask {virtual.mask}")
    if virtual.ip_protocol:
        parts.append(f"ip-protocol {virtual.ip_protocol}")
    if virtual.default_pool:
        parts.append(f"pool {virtual.default_pool}")
    if virtual.profiles:
        profiles = " ".join(
            f"{profile.full_path} {{ context {profile.context} }}" for profile in virtual.profiles
        )
        parts.append(f"profiles add {{ {profiles} }}")
    if virtual.irules:
        # Order is execution order: keep the configured list as is.
        parts.append(f"rules {{ {' '.join(virtual.irules)} }}")
    if virtual.policies:
        parts.append(f"policies add {{ {' '.join(virtual.policies)} }}")
    if virtual.persistence:
        first, *rest = virtual.persistence
        profiles = " ".join([f"{first} {{ default yes }}", *rest])
        parts.append(f"persist replace-all-with {{ {profiles} }}")
    if virtual.fallback_persistence:
        parts.append(f"fallback-persistence {virtual.fallback_persistence}")
    if virtual.snat_type == "snat" and virtual.snat_pool:
        parts.append(f"source-address-translation {{ type snat pool {virtual.snat_pool} }}")
    elif virtual.snat_type and virtual.snat_type != "none":
        parts.append(f"source-address-translation {{ type {virtual.snat_type} }}")
    if virtual.vlans_enabled:
        parts.append("vlans-enabled")
    if virtual.vlans:
        if not virtual.vlans_enabled:
            parts.append("vlans-disabled")
        parts.append(f"vlans add {{ {' '.join(virtual.vlans)} }}")
    if virtual.translate_address == "disabled":
        parts.append("translate-address disabled")
    if virtual.translate_port == "disabled":
        parts.append("translate-port disabled")
    if virtual.source not in ANY_SOURCE:
        parts.append(f"source {virtual.source}")
    if virtual.connection_limit:
        parts.append(f"connection-limit {virtual.connection_limit}")
    if virtual.description:
        parts.append(f"description {_quote(virtual.description)}")
    if virtual.admin_state == "disabled":
        parts.append("disabled")
    return " ".join(parts)
