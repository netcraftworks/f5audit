"""Collection orchestration: fetch every endpoint the audit needs.

Also implements the raw cache: ``--save-raw`` writes every JSON response
to disk, ``--from-raw`` re-analyzes from disk without touching the F5.
Each raw file carries its collection timestamp so a future ``compare``
subcommand can diff two collections taken weeks apart.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .client import F5APIError, F5ClientError, F5ReadOnlyClient

logger = logging.getLogger("f5audit.collector")

# Monitor types to enumerate; 404 on a type means it is not provisioned
# on that BIG-IP and is silently skipped.
MONITOR_TYPES = [
    "http",
    "https",
    "tcp",
    "tcp-half-open",
    "udp",
    "icmp",
    "gateway-icmp",
    "external",
    "ldap",
    "dns",
    "mysql",
    "sip",
]

META_KEY = "_meta"

_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._@~-]")


def encode_path_component(full_path: str) -> str:
    """iControl REST encodes '/' as '~' in object identifiers."""
    return full_path.replace("/", "~")


@dataclass
class CollectionData:
    """All raw JSON datasets plus collection metadata."""

    datasets: dict[str, Any] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.datasets.get(key, default)

    def keys_with_prefix(self, prefix: str) -> list[str]:
        return sorted(k for k in self.datasets if k.startswith(prefix))


class RawStore:
    """Persists one JSON file per dataset, with timestamp metadata."""

    def __init__(self, directory: str):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _filename(self, key: str) -> Path:
        return self.directory / (_UNSAFE_FILENAME_CHARS.sub("_", key) + ".json")

    def save(self, key: str, api_path: str, data: Any) -> None:
        payload = {
            "key": key,
            "path": api_path,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        with open(self._filename(key), "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=1)

    def save_meta(self, meta: dict[str, Any]) -> None:
        with open(self._filename(META_KEY), "w", encoding="utf-8") as handle:
            json.dump(meta, handle, indent=1)

    def load_all(self) -> CollectionData:
        result = CollectionData()
        files = sorted(self.directory.glob("*.json"))
        if not files:
            raise F5ClientError(
                f"No raw JSON files found in {self.directory}. "
                "Run 'f5audit collect --save-raw <dir>' first."
            )
        for path in files:
            try:
                with open(path, encoding="utf-8") as handle:
                    payload = json.load(handle)
            except (ValueError, OSError) as exc:
                raise F5ClientError(f"Could not read raw file {path}: {exc}") from exc
            if path.stem == META_KEY:
                result.meta = payload
            else:
                result.datasets[payload.get("key", path.stem)] = payload.get("data")
        return result


class Collector:
    """Runs the full read-only collection against a BIG-IP."""

    def __init__(
        self,
        client: F5ReadOnlyClient,
        raw_store: RawStore | None = None,
        *,
        resume_data: CollectionData | None = None,
    ):
        self.client = client
        self.raw_store = raw_store
        self.data = CollectionData()
        now = datetime.now(timezone.utc).isoformat()
        previous_meta = resume_data.meta if resume_data else {}
        if resume_data:
            self.data.datasets = dict(resume_data.datasets)
        self.data.meta = {
            # A resumed run keeps the original timestamp; per-file
            # timestamps in the RawStore record when each dataset landed.
            "collected_at": previous_meta.get("collected_at") or now,
            "host": getattr(client, "_host", ""),
            "denied": [],  # [{"partition": ..., "endpoint": ...}]
            "missing_endpoints": [],  # ["ltm/virtual/stats", ...]
            "aborted": None,
        }
        if resume_data:
            # Gaps are re-evaluated: what failed before has no dataset and
            # gets one fresh attempt; what succeeded is skipped in _fetch.
            resumed_at = list(previous_meta.get("resumed_at") or [])
            resumed_at.append(now)
            self.data.meta["resumed_at"] = resumed_at

    # ------------------------------------------------------------------

    def _store(self, key: str, api_path: str, data: Any) -> None:
        self.data.datasets[key] = data
        if self.raw_store:
            self.raw_store.save(key, api_path, data)

    def _fetch(
        self,
        key: str,
        api_path: str,
        *,
        collection: bool = True,
        params: dict[str, Any] | None = None,
        partition: str | None = None,
        tolerate_404: bool = False,
    ) -> Any | None:
        """Fetch one dataset, recording 403/404 instead of failing.

        403 -> recorded (denied partition or missing endpoint), returns None.
        404 -> returns None silently when tolerated (e.g. monitor types),
               otherwise recorded as a missing endpoint.

        A dataset seeded from a previous run (resume) is never re-fetched:
        pointing --save-raw at an existing cache only fills the gaps.
        """
        if self.data.datasets.get(key) is not None:
            logger.debug("Skipping %s (already collected)", key)
            return self.data.datasets[key]
        try:
            if collection:
                data: Any = self.client.get_collection(api_path, params=params)
            else:
                data = self.client.get(api_path, params=params)
        except F5APIError as exc:
            if exc.status_code == 403:
                logger.warning("Access denied (403) on %s", api_path)
                self.data.meta["denied"].append({"partition": partition, "endpoint": api_path})
                return None
            if exc.status_code == 404:
                if not tolerate_404:
                    logger.warning("Endpoint not found (404): %s", api_path)
                    self.data.meta["missing_endpoints"].append(api_path)
                return None
            raise
        self._store(key, api_path, data)
        return data

    # ------------------------------------------------------------------

    def collect(self) -> CollectionData:
        """Run the whole collection; on a persistent connection failure,
        stop cleanly and keep whatever was already gathered (and saved).
        """
        try:
            self._collect_system()
            partitions = self._collect_partitions()
            for partition in partitions:
                self._collect_partition_config(partition)
            self._collect_pool_details()
            self._collect_virtual_details()
            self._collect_policy_rules()
            self._collect_monitors(partitions)
            self._collect_stats()
            self._collect_network()
        except F5ClientError as exc:
            self.data.meta["aborted"] = str(exc)
            logger.error(
                "Collection aborted: %s. Datasets gathered so far: %d",
                exc,
                len(self.data.datasets),
            )
        finally:
            if self.raw_store:
                self.raw_store.save_meta(self.data.meta)
        return self.data

    def _collect_system(self) -> None:
        logger.info("Collecting system information...")
        self._fetch("sys_version", "/mgmt/tm/sys/version", collection=False)
        self._fetch("sys_failover", "/mgmt/tm/sys/failover", collection=False)
        self._fetch("sys_clock", "/mgmt/tm/sys/clock", collection=False)
        self._fetch("cm_device", "/mgmt/tm/cm/device")

    def _collect_partitions(self) -> list[str]:
        items = self._fetch("auth_partition", "/mgmt/tm/auth/partition")
        if not items:
            logger.warning("Could not enumerate partitions; assuming only Common.")
            return ["Common"]
        return [item.get("name", "") for item in items if item.get("name")]

    def _collect_partition_config(self, partition: str) -> None:
        logger.info("Collecting configuration for partition %s...", partition)
        params = {"$filter": f"partition eq {partition}"}
        for short, api_path in (
            ("ltm_node", "/mgmt/tm/ltm/node"),
            ("ltm_pool", "/mgmt/tm/ltm/pool"),
            ("ltm_virtual", "/mgmt/tm/ltm/virtual"),
            ("ltm_rule", "/mgmt/tm/ltm/rule"),
            ("ltm_policy", "/mgmt/tm/ltm/policy"),
        ):
            self._fetch(
                f"{short}@{partition}",
                api_path,
                params=dict(params),
                partition=partition,
            )

    def _iter_object_paths(self, prefix: str) -> list[str]:
        paths = []
        for key in self.data.keys_with_prefix(prefix + "@"):
            for item in self.data.datasets.get(key) or []:
                full_path = item.get("fullPath")
                if full_path:
                    paths.append(full_path)
        return paths

    def _collect_pool_details(self) -> None:
        pools = self._iter_object_paths("ltm_pool")
        logger.info("Collecting members for %d pools...", len(pools))
        for full_path in pools:
            encoded = encode_path_component(full_path)
            self._fetch(
                f"ltm_pool_members@{full_path}",
                f"/mgmt/tm/ltm/pool/{encoded}/members",
            )
            self._fetch(
                f"ltm_pool_member_stats@{full_path}",
                f"/mgmt/tm/ltm/pool/{encoded}/members/stats",
                collection=False,
                tolerate_404=True,
            )

    def _collect_virtual_details(self) -> None:
        """Attached policies (correlation) and profiles (rollback commands).
        Profiles are a subcollection: the virtual collection only carries a
        link to them, and expanding it over every virtual is off-limits."""
        virtuals = self._iter_object_paths("ltm_virtual")
        logger.info(
            "Collecting attached policies and profiles for %d virtual servers...", len(virtuals)
        )
        for full_path in virtuals:
            encoded = encode_path_component(full_path)
            for subcollection in ("policies", "profiles"):
                self._fetch(
                    f"ltm_virtual_{subcollection}@{full_path}",
                    f"/mgmt/tm/ltm/virtual/{encoded}/{subcollection}",
                    tolerate_404=True,
                )

    def _collect_policy_rules(self) -> None:
        policies = self._iter_object_paths("ltm_policy")
        logger.info("Collecting rules/actions for %d policies...", len(policies))
        for full_path in policies:
            encoded = encode_path_component(full_path)
            # expandSubcollections only on a single object, never on the
            # whole collection (management-plane load, spec section 2.6).
            self._fetch(
                f"ltm_policy_rules@{full_path}",
                f"/mgmt/tm/ltm/policy/{encoded}/rules",
                params={"expandSubcollections": "true"},
                tolerate_404=True,
            )

    def _collect_monitors(self, partitions: list[str]) -> None:
        logger.info("Collecting monitors...")
        for monitor_type in MONITOR_TYPES:
            for partition in partitions:
                data = self._fetch(
                    f"ltm_monitor_{monitor_type}@{partition}",
                    f"/mgmt/tm/ltm/monitor/{monitor_type}",
                    params={"$filter": f"partition eq {partition}"},
                    partition=partition,
                    tolerate_404=True,
                )
                if data is None and self._monitor_type_missing(monitor_type):
                    # Type not provisioned at all: skip remaining partitions.
                    break

    def _monitor_type_missing(self, monitor_type: str) -> bool:
        return not any(key.startswith(f"ltm_monitor_{monitor_type}@") for key in self.data.datasets)

    def _collect_stats(self) -> None:
        logger.info("Collecting statistics...")
        # Stats endpoints return a single 'entries' document, not a
        # paginated collection.
        self._fetch("ltm_virtual_stats", "/mgmt/tm/ltm/virtual/stats", collection=False)
        self._fetch("ltm_pool_stats", "/mgmt/tm/ltm/pool/stats", collection=False)
        self._fetch("ltm_node_stats", "/mgmt/tm/ltm/node/stats", collection=False)

    def _collect_network(self) -> None:
        """L2/L3 context for the report: self-IP subnets and the ARP
        table (dynamic entries live under /stats, static under the plain
        collection). All tolerant: a denied or missing endpoint degrades
        the network columns, never the audit. NDP (IPv6 neighbors) is
        cached for future use but not parsed yet.
        """
        logger.info("Collecting network tables (self-IPs, ARP)...")
        self._fetch("net_self", "/mgmt/tm/net/self", tolerate_404=True)
        self._fetch("net_arp", "/mgmt/tm/net/arp", tolerate_404=True)
        self._fetch("net_arp_stats", "/mgmt/tm/net/arp/stats", collection=False, tolerate_404=True)
        self._fetch("net_ndp_stats", "/mgmt/tm/net/ndp/stats", collection=False, tolerate_404=True)


def load_from_raw(directory: str) -> CollectionData:
    """Load a previous collection from disk (offline mode)."""
    return RawStore(directory).load_all()
