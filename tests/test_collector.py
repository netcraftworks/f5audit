"""Collector tests: raw cache roundtrip, 403/404 handling. No network."""

import pytest

from f5audit.client import F5APIError, F5ClientError
from f5audit.collector import Collector, RawStore, load_from_raw
from tests.conftest import build_collection, load_fixture


class FakeClient:
    """Stands in for F5ReadOnlyClient; serves canned responses per path."""

    page_size = 100
    _host = "192.0.2.1"

    def __init__(self, responses):
        # responses: {path: data} or {path: F5APIError instance}
        self.responses = responses
        self.requested = []

    def _serve(self, path):
        self.requested.append(path)
        result = self.responses.get(path)
        if isinstance(result, F5APIError):
            raise result
        return result

    def get(self, path, params=None):
        data = self._serve(path)
        if data is None:
            raise F5APIError(404, path)
        return data

    def get_collection(self, path, params=None):
        data = self._serve(path)
        if data is None:
            raise F5APIError(404, path)
        return data


def minimal_responses():
    return {
        "/mgmt/tm/sys/version": load_fixture("sys_version.json"),
        "/mgmt/tm/sys/failover": load_fixture("sys_failover_active.json"),
        "/mgmt/tm/sys/clock": {},
        "/mgmt/tm/cm/device": load_fixture("cm_device.json"),
        "/mgmt/tm/auth/partition": load_fixture("auth_partition.json"),
        "/mgmt/tm/ltm/node": load_fixture("nodes.json"),
        "/mgmt/tm/ltm/pool": [load_fixture("pools.json")[0]],
        "/mgmt/tm/ltm/virtual": [],
        "/mgmt/tm/ltm/rule": [],
        "/mgmt/tm/ltm/policy": [],
        "/mgmt/tm/ltm/pool/~Common~pool-web/members": load_fixture("pool_members_pool-web.json"),
        "/mgmt/tm/ltm/pool/~Common~pool-web/members/stats": load_fixture(
            "pool_member_stats_pool-web.json"
        ),
        "/mgmt/tm/ltm/monitor/http": load_fixture("monitors_http.json"),
        "/mgmt/tm/ltm/virtual/stats": {},
        "/mgmt/tm/ltm/pool/stats": {},
        "/mgmt/tm/ltm/node/stats": {},
        "/mgmt/tm/net/self": load_fixture("net_self.json"),
        "/mgmt/tm/net/arp": load_fixture("net_arp.json"),
        "/mgmt/tm/net/arp/stats": load_fixture("net_arp_stats.json"),
    }


def test_collect_gathers_expected_datasets():
    collector = Collector(FakeClient(minimal_responses()))
    data = collector.collect()

    assert data.meta["aborted"] is None
    assert data.get("sys_version")
    assert data.get("ltm_node@Common")
    assert data.get("ltm_pool_members@/Common/pool-web")
    # Unprovisioned monitor types (404) are skipped silently.
    assert "ltm_monitor_mysql@Common" not in data.datasets
    assert "/mgmt/tm/ltm/monitor/mysql" not in data.meta["missing_endpoints"]
    assert data.get("ltm_monitor_http@Common")


def test_collect_gathers_network_datasets():
    collector = Collector(FakeClient(minimal_responses()))
    data = collector.collect()

    assert data.get("net_self")
    assert data.get("net_arp")
    assert data.get("net_arp_stats")
    # NDP is not served by the fake (404) and is tolerated silently.
    assert "net_ndp_stats" not in data.datasets
    assert "/mgmt/tm/net/ndp/stats" not in data.meta["missing_endpoints"]
    assert data.meta["aborted"] is None


def test_collect_tolerates_denied_network_endpoints():
    responses = minimal_responses()
    responses["/mgmt/tm/net/arp/stats"] = F5APIError(403, "/mgmt/tm/net/arp/stats")
    collector = Collector(FakeClient(responses))
    data = collector.collect()

    assert "net_arp_stats" not in data.datasets
    assert any(entry["endpoint"] == "/mgmt/tm/net/arp/stats" for entry in data.meta["denied"])
    assert data.meta["aborted"] is None


def test_collect_records_403_as_denied():
    responses = minimal_responses()
    responses["/mgmt/tm/ltm/rule"] = F5APIError(403, "/mgmt/tm/ltm/rule")
    collector = Collector(FakeClient(responses))
    data = collector.collect()

    denied = data.meta["denied"]
    assert any(
        entry["endpoint"] == "/mgmt/tm/ltm/rule" and entry["partition"] == "Common"
        for entry in denied
    )
    assert data.meta["aborted"] is None


def test_collect_aborts_cleanly_on_connection_failure():
    responses = minimal_responses()

    class DyingClient(FakeClient):
        def get_collection(self, path, params=None):
            if path == "/mgmt/tm/ltm/virtual":
                raise F5ClientError("GET failed after 3 attempts: Timeout")
            return super().get_collection(path, params)

    collector = Collector(DyingClient(responses))
    data = collector.collect()

    assert "Timeout" in data.meta["aborted"]
    # Earlier datasets were kept.
    assert data.get("sys_version")
    assert data.get("ltm_node@Common")


def test_raw_store_roundtrip(tmp_path):
    original = build_collection()
    store = RawStore(str(tmp_path))
    for key, dataset in original.datasets.items():
        store.save(key, f"/mgmt/fake/{key}", dataset)
    store.save_meta(original.meta)

    loaded = load_from_raw(str(tmp_path))

    assert loaded.datasets == original.datasets
    assert loaded.meta == original.meta


def test_raw_files_carry_timestamp(tmp_path):
    store = RawStore(str(tmp_path))
    store.save("sys_version", "/mgmt/tm/sys/version", {"x": 1})
    import json

    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text())
    assert payload["collected_at"]  # enables the future compare subcommand
    assert payload["path"] == "/mgmt/tm/sys/version"


def test_load_from_raw_empty_dir_errors(tmp_path):
    with pytest.raises(F5ClientError):
        load_from_raw(str(tmp_path))


def test_resumed_collection_fetches_only_missing_datasets(tmp_path):
    # First run against a device where the net/* endpoints do not exist:
    # the raw cache ends up without the network datasets.
    responses = minimal_responses()
    partial = {
        path: data for path, data in responses.items() if not path.startswith("/mgmt/tm/net/")
    }
    first = Collector(FakeClient(partial), raw_store=RawStore(str(tmp_path)))
    first_data = first.collect()
    assert "net_self" not in first_data.datasets

    # Second run resumes from the same directory: only the gaps are fetched.
    client = FakeClient(responses)
    second = Collector(
        client, raw_store=RawStore(str(tmp_path)), resume_data=load_from_raw(str(tmp_path))
    )
    data = second.collect()

    assert {p for p in client.requested if p.startswith("/mgmt/tm/net/")} == {
        "/mgmt/tm/net/self",
        "/mgmt/tm/net/arp",
        "/mgmt/tm/net/arp/stats",
        "/mgmt/tm/net/ndp/stats",
    }
    # Datasets that already have a file are never re-fetched.
    assert "/mgmt/tm/sys/version" not in client.requested
    assert "/mgmt/tm/ltm/node" not in client.requested
    assert "/mgmt/tm/ltm/pool/~Common~pool-web/members" not in client.requested
    assert data.get("net_self")
    assert data.get("sys_version")  # carried over from the first run
    assert data.meta["aborted"] is None


def test_resumed_collection_keeps_original_timestamp_and_records_resume(tmp_path):
    first = Collector(FakeClient(minimal_responses()), raw_store=RawStore(str(tmp_path)))
    first_data = first.collect()

    second = Collector(
        FakeClient(minimal_responses()),
        raw_store=RawStore(str(tmp_path)),
        resume_data=load_from_raw(str(tmp_path)),
    )
    data = second.collect()

    assert data.meta["collected_at"] == first_data.meta["collected_at"]
    assert len(data.meta["resumed_at"]) == 1
    # Gaps from the previous run are re-evaluated, not inherited.
    assert data.meta["denied"] == []
    assert data.meta["aborted"] is None


def test_resumed_collection_retries_previous_failures(tmp_path):
    responses = minimal_responses()
    responses["/mgmt/tm/ltm/rule"] = F5APIError(403, "/mgmt/tm/ltm/rule")
    first = Collector(FakeClient(responses), raw_store=RawStore(str(tmp_path)))
    first_data = first.collect()
    assert "ltm_rule@Common" not in first_data.datasets

    # Permissions fixed: the resumed run fills the gap and clears 'denied'.
    client = FakeClient(minimal_responses())
    second = Collector(
        client, raw_store=RawStore(str(tmp_path)), resume_data=load_from_raw(str(tmp_path))
    )
    data = second.collect()

    assert "/mgmt/tm/ltm/rule" in client.requested
    assert data.get("ltm_rule@Common") == []
    assert data.meta["denied"] == []


def test_collect_fetches_virtual_policies_and_profiles_per_virtual():
    responses = minimal_responses()
    responses["/mgmt/tm/ltm/virtual"] = [load_fixture("virtuals.json")[2]]  # vs-dead
    responses["/mgmt/tm/ltm/virtual/~Common~vs-dead/policies"] = []
    responses["/mgmt/tm/ltm/virtual/~Common~vs-dead/profiles"] = load_fixture(
        "virtual_profiles_vs-dead.json"
    )
    client = FakeClient(responses)
    data = Collector(client).collect()

    assert data.get("ltm_virtual_policies@/Common/vs-dead") == []
    assert len(data.get("ltm_virtual_profiles@/Common/vs-dead")) == 3
    # Per-object subcollections only: never expandSubcollections over a list.
    assert "/mgmt/tm/ltm/virtual/~Common~vs-dead/profiles" in client.requested


def test_collect_tolerates_missing_virtual_profiles():
    responses = minimal_responses()
    responses["/mgmt/tm/ltm/virtual"] = [load_fixture("virtuals.json")[2]]
    data = Collector(FakeClient(responses)).collect()

    assert data.meta["aborted"] is None
    assert "ltm_virtual_profiles@/Common/vs-dead" not in data.datasets
    assert not any("profiles" in endpoint for endpoint in data.meta["missing_endpoints"])
