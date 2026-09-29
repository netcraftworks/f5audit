"""Shared fixtures. No test in this suite ever touches the network."""

import json
from pathlib import Path

import pytest

from f5audit.collector import CollectionData

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name):
    with open(FIXTURES_DIR / name, encoding="utf-8") as handle:
        return json.load(handle)


def build_collection(
    *, standby: bool = False, denied=None, missing_endpoints=None, network: bool = True
) -> CollectionData:
    """Assemble a CollectionData equivalent to a full live collection.

    network=False simulates a raw cache from before the net_* datasets
    were collected.
    """
    data = CollectionData()
    data.meta = {
        "collected_at": "2026-08-19T12:00:00+00:00",
        "host": "192.0.2.1",
        "denied": denied or [],
        "missing_endpoints": missing_endpoints or [],
        "aborted": None,
    }
    failover = "sys_failover_standby.json" if standby else "sys_failover_active.json"
    vs_stats = "virtual_stats_zero.json" if standby else "virtual_stats.json"
    data.datasets = {
        "sys_version": load_fixture("sys_version.json"),
        "sys_failover": load_fixture(failover),
        "sys_clock": {},
        "cm_device": load_fixture("cm_device.json"),
        "auth_partition": load_fixture("auth_partition.json"),
        "ltm_node@Common": load_fixture("nodes.json"),
        "ltm_pool@Common": load_fixture("pools.json"),
        "ltm_virtual@Common": load_fixture("virtuals.json"),
        "ltm_rule@Common": load_fixture("rules.json"),
        "ltm_policy@Common": [],
        "ltm_pool_members@/Common/pool-web": load_fixture("pool_members_pool-web.json"),
        "ltm_pool_members@/Common/pool-orphan": [],
        "ltm_pool_members@/Common/pool-irule": load_fixture("pool_members_pool-irule.json"),
        "ltm_pool_members@/Common/pool-idle": load_fixture("pool_members_pool-idle.json"),
        "ltm_pool_members@/Common/pool-dead": load_fixture("pool_members_pool-dead.json"),
        "ltm_pool_member_stats@/Common/pool-web": load_fixture("pool_member_stats_pool-web.json"),
        "ltm_pool_member_stats@/Common/pool-dead": load_fixture("pool_member_stats_pool-dead.json"),
        "ltm_virtual_profiles@/Common/vs-dead": load_fixture("virtual_profiles_vs-dead.json"),
        "ltm_virtual_stats": load_fixture(vs_stats),
        "ltm_pool_stats": load_fixture("pool_stats.json"),
        "ltm_node_stats": load_fixture("node_stats.json"),
        "ltm_monitor_http@Common": load_fixture("monitors_http.json"),
    }
    if network:
        data.datasets["net_self"] = load_fixture("net_self.json")
        data.datasets["net_arp"] = load_fixture("net_arp.json")
        data.datasets["net_arp_stats"] = load_fixture("net_arp_stats.json")
    return data


@pytest.fixture
def collection_active():
    return build_collection()


@pytest.fixture
def collection_standby():
    return build_collection(standby=True)
