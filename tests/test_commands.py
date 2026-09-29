"""tmsh command text builders: syntax per the official tmsh reference."""

from f5audit import commands
from f5audit.models import Node, Pool, PoolMember, VirtualProfile, VirtualServer


def member(node_path, port, **kwargs):
    return PoolMember(node_full_path=node_path, port=port, partition="Common", **kwargs)


def test_member_ref_uses_dot_for_ipv6_named_nodes():
    assert commands.member_ref("/Common/web-1", "80") == "/Common/web-1:80"
    assert commands.member_ref("/Common/2001:db8::10", "443") == "/Common/2001:db8::10.443"


def test_node_create_command_ip_fqdn_and_monitor():
    node = Node("/Common/web-1", "Common", "web-1", address="10.0.0.1", monitor="/Common/icmp")
    assert commands.node_create_command(node) == (
        "create ltm node /Common/web-1 address 10.0.0.1 monitor /Common/icmp"
    )
    fqdn = Node("/Common/app", "Common", "app", address="app.example.net", monitor="default")
    assert commands.node_create_command(fqdn) == (
        "create ltm node /Common/app fqdn { name app.example.net }"
    )


def test_member_commands_carry_non_default_member_settings():
    target = member("/Common/web-1", "80", priority_group=10, ratio=2, admin_state="user-disabled")
    assert commands.remove_member_command("/Common/p", target) == (
        "modify ltm pool /Common/p members delete { /Common/web-1:80 }"
    )
    assert commands.add_member_command("/Common/p", target) == (
        "modify ltm pool /Common/p members add { /Common/web-1:80 "
        "{ priority-group 10 ratio 2 session user-disabled } }"
    )


def test_pool_create_command_full():
    pool = Pool(
        "/Common/p",
        "Common",
        "p",
        monitor_expression="min 1 of { /Common/http /Common/tcp }",
        lb_method="least-connections-member",
        min_active_members=1,
        slow_ramp_time=30,
        service_down_action="reset",
        description='web "tier"',
        members=[member("/Common/web-1", "80", priority_group=10), member("/Common/web-2", "80")],
    )
    assert commands.pool_create_command(pool) == (
        "create ltm pool /Common/p members add { /Common/web-1:80 { priority-group 10 } "
        "/Common/web-2:80 } monitor min 1 of { /Common/http /Common/tcp } "
        "load-balancing-mode least-connections-member min-active-members 1 "
        'slow-ramp-time 30 service-down-action reset description "web \\"tier\\""'
    )


def test_pool_create_command_empty_pool_omits_members_and_defaults():
    pool = Pool("/Common/p", "Common", "p", lb_method="round-robin", members_collected=True)
    assert commands.pool_create_command(pool) == "create ltm pool /Common/p"


def test_detach_and_reattach_pool():
    assert commands.detach_pool_command("/Common/vs") == "modify ltm virtual /Common/vs pool none"
    assert commands.reattach_pool_command("/Common/vs", "/Common/p") == (
        "modify ltm virtual /Common/vs pool /Common/p"
    )


def make_virtual(**kwargs):
    defaults = dict(
        full_path="/Common/vs",
        partition="Common",
        name="vs",
        destination="192.0.2.10:443",
        destination_path="/Common/192.0.2.10:443",
        profiles_collected=True,
    )
    defaults.update(kwargs)
    return VirtualServer(**defaults)


def test_virtual_create_command_without_profiles_collected_is_empty():
    assert commands.virtual_create_command(make_virtual(profiles_collected=False)) == ""


def test_virtual_create_command_full():
    virtual = make_virtual(
        mask="255.255.255.255",
        ip_protocol="tcp",
        default_pool="/Common/p",
        profiles=[VirtualProfile("/Common/tcp"), VirtualProfile("/Common/ssl", "clientside")],
        irules=["/Common/r2", "/Common/r1"],
        policies=["/Common/pol"],
        persistence=["/Common/cookie"],
        snat_type="automap",
        vlans=["/Common/internal"],
        translate_port="disabled",
        source="198.51.100.0/24",
        connection_limit=500,
        admin_state="disabled",
    )
    assert commands.virtual_create_command(virtual) == (
        "create ltm virtual /Common/vs destination /Common/192.0.2.10:443 "
        "mask 255.255.255.255 ip-protocol tcp pool /Common/p "
        "profiles add { /Common/tcp { context all } /Common/ssl { context clientside } } "
        "rules { /Common/r2 /Common/r1 } policies add { /Common/pol } "
        "persist replace-all-with { /Common/cookie { default yes } } "
        "source-address-translation { type automap } "
        "vlans-disabled vlans add { /Common/internal } translate-port disabled "
        "source 198.51.100.0/24 connection-limit 500 disabled"
    )


def test_virtual_create_command_ipv6_destination_is_kept_verbatim():
    virtual = make_virtual(destination_path="/Common/2001:db8::10.443")
    assert commands.virtual_create_command(virtual) == (
        "create ltm virtual /Common/vs destination /Common/2001:db8::10.443"
    )


def test_delete_commands():
    assert commands.delete_node_command("/Common/n") == "delete ltm node /Common/n"
    assert commands.delete_pool_command("/Common/p") == "delete ltm pool /Common/p"
    assert commands.delete_virtual_command("/Common/v") == "delete ltm virtual /Common/v"
