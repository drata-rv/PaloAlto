"""
pan_main.py
Palo Alto Networks (PAN-OS / Panorama) compliance evidence collector.

Collects license status, URL Filtering / DNS Security (Anti-Spyware)
profiles, security policy rules, and traffic/URL/threat log summaries from
PAN-OS firewalls and Panorama, normalizes them to the Drata evidence schema
(pan_drata_schemas.py), and publishes them to a Drata Custom Connection
(pan_drata_publisher.py) via a registry-driven connector -> normalizer ->
publisher pipeline.

Several data points rely on parsing logic that is NOT independently
confirmed against official Palo Alto documentation (see pan_api_research.md,
"Items That Must Be Confirmed"). Every such gap is flagged in the relevant
connector method's docstring in pan_firewall.py, in pan_drata_schemas.py
where it affects normalization, and via a runtime log warning. A clean run
of this script is not proof those gaps are closed -- inspect the raw
responses logged on first run against a real device.

Device topology this connector is built to handle:
    - Direct-access firewalls: reachable directly on their own management
      hostname, not Panorama-managed.
    - Panorama-managed firewalls: license info is always proxied through
      Panorama (confirmed to work via target=<serial>) regardless of
      whether a direct host is also configured for the firewall. Profiles/
      rules/logs on these still require direct reachability to the firewall
      itself, UNLESS you'd rather pull Panorama's own device-group
      definitions instead (the *intended* push state rather than each
      firewall's *actual applied* state) -- device groups produce their own
      DEVICE_GROUP-scoped records.

Device inventory (hostnames, serials, device groups) is supplied via a JSON
config file -- see devices.example.json for the expected shape. No real
hostnames/IPs/serials are hardcoded anywhere in this codebase.

Credentials are a single dedicated, least-privilege service account -- see
README.md for the exact PAN-OS API permissions this connector needs.

Required environment variables:
    PAN_USERNAME
    PAN_PASSWORD
Required unless --collect-only:
    DRATA_API_KEY
    PAN_DRATA_CONNECTION_ID
    PAN_DRATA_RESOURCE_ID

The Drata connection/resource vars are PAN_-prefixed (DRATA_API_KEY is not)
so this connector can be deployed alongside another Drata custom connection
in a shared Azure Function App without colliding on App Settings names --
those are shared app-wide across every function in an app. DRATA_API_KEY is
left unprefixed on the assumption it's one account-level key valid for any
Custom Connection; confirm that before relying on it if provisioning is
per-connection instead.

Usage:
    python3 pan_main.py --devices-config devices.json --output pan_payload.json
    python3 pan_main.py --devices-config devices.json --collect-only
    python3 pan_main.py --devices-config devices.json --resources license,security_rule

Drata SA Team
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Callable, Dict, FrozenSet, List, Optional

import pan_drata_schemas as schemas
from pan_auth import PanAuthClient
from pan_drata_publisher import DrataPublisher
from pan_firewall import PanFirewallConnector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when devices.json (or the environment) is structurally invalid."""


# ----------------------------------------------------------------------
# Device model
# ----------------------------------------------------------------------

@dataclass
class DeviceContext:
    """
    One evidence-collection target: either an individual firewall (direct
    or Panorama-managed) or a Panorama device-group.

    `connector` is the object used for profile/rule/log calls -- None for a
    Panorama-managed firewall with no direct `host` configured (those calls
    require direct reachability per pan_api_research.md section 5/6 and are
    skipped, matching the original prototype's behavior).

    `license_connector` is always set for FIREWALL-scoped devices: either
    the same direct connector (non-Panorama-managed firewalls), or a thin
    adapter that proxies through Panorama with target=<serial> (confirmed
    to work for license info regardless of whether `host` is also
    configured -- see pan_api_research.md section 6).
    """
    id: str
    hostname: str
    scope: str  # "FIREWALL" | "DEVICE_GROUP"
    managed_by: str  # "DIRECT" | "PANORAMA"
    site: str
    vsys: Optional[str] = None
    device_group: Optional[str] = None
    connector: Optional[PanFirewallConnector] = None
    license_connector: Optional[object] = None


# ----------------------------------------------------------------------
# Resource registry -- the single source of truth mapping each evidence
# type to the connector method that fetches it, the normalizer that
# shapes it for Drata, and which device scopes it applies to.
# ----------------------------------------------------------------------

@dataclass
class _Resource:
    key: str
    method_name: str
    normalizer: Callable
    evidence_type: str
    label: str
    scopes: FrozenSet[str]
    connector_attr: str = "connector"
    is_aggregate: bool = False
    call_kwargs: Callable[[DeviceContext], dict] = field(default=lambda d: {})
    normalizer_kwargs: dict = field(default_factory=dict)


def _location_kwargs(device: DeviceContext) -> dict:
    """Shared by profile resources, which are callable at both FIREWALL
    (location=vsys) and DEVICE_GROUP (location=device-group) scope."""
    if device.scope == "DEVICE_GROUP":
        return {"location": "device-group", "device_group": device.device_group}
    return {"location": "vsys", "vsys": device.vsys}


# Best-effort DNS threat query: PAN-OS's confirmed-correct filter field is
# `category-of-threatid` (NOT `subtype`, per pan_api_research.md section 5),
# but the full category value enumeration is an open gap -- only a handful
# of example values are documented. This OR's together every example value
# found in that research pass; revisit once the full list is confirmed
# against a live device.
_DNS_THREAT_QUERY = (
    "(category-of-threatid eq dns-c2) or (category-of-threatid eq adns-hijacking) "
    "or (category-of-threatid eq ddns) or (category-of-threatid eq parked) "
    "or (category-of-threatid eq malware)"
)

_RESOURCE_REGISTRY: List[_Resource] = [
    _Resource(
        key="license", method_name="get_license_info",
        normalizer=schemas.normalize_license,
        evidence_type="FIREWALL_LICENSE", label="Firewall License",
        scopes=frozenset({"FIREWALL"}), connector_attr="license_connector",
    ),
    _Resource(
        key="url_filtering_profile", method_name="get_url_filtering_profiles",
        normalizer=schemas.normalize_url_filtering_profile,
        evidence_type="URL_FILTERING_PROFILE", label="URL Filtering Profile",
        scopes=frozenset({"FIREWALL", "DEVICE_GROUP"}), call_kwargs=_location_kwargs,
    ),
    _Resource(
        key="dns_security_profile", method_name="get_dns_security_profiles",
        normalizer=schemas.normalize_dns_security_profile,
        evidence_type="DNS_SECURITY_PROFILE", label="DNS Security Profile",
        scopes=frozenset({"FIREWALL", "DEVICE_GROUP"}), call_kwargs=_location_kwargs,
    ),
    _Resource(
        key="security_rule", method_name="get_security_rules",
        normalizer=schemas.normalize_security_rule,
        evidence_type="SECURITY_RULE", label="Security Rule",
        scopes=frozenset({"FIREWALL"}), call_kwargs=_location_kwargs,
        normalizer_kwargs={"rule_scope": "LOCAL"},
    ),
    _Resource(
        key="security_pre_rule", method_name="get_security_pre_rules",
        normalizer=schemas.normalize_security_rule,
        evidence_type="SECURITY_RULE", label="Security Pre-Rule",
        scopes=frozenset({"DEVICE_GROUP"}), call_kwargs=lambda d: {"device_group": d.device_group},
        normalizer_kwargs={"rule_scope": "PRE_RULE"},
    ),
    _Resource(
        key="security_post_rule", method_name="get_security_post_rules",
        normalizer=schemas.normalize_security_rule,
        evidence_type="SECURITY_RULE", label="Security Post-Rule",
        scopes=frozenset({"DEVICE_GROUP"}), call_kwargs=lambda d: {"device_group": d.device_group},
        normalizer_kwargs={"rule_scope": "POST_RULE"},
    ),
    _Resource(
        key="traffic_log_summary", method_name="get_traffic_logs",
        normalizer=schemas.normalize_traffic_log_summary,
        evidence_type="TRAFFIC_LOG_SUMMARY", label="Traffic Log Summary",
        scopes=frozenset({"FIREWALL"}), call_kwargs=lambda d: {"nlogs": 1000},
        is_aggregate=True,
    ),
    _Resource(
        key="url_filtering_log_summary", method_name="get_url_filtering_logs",
        normalizer=schemas.normalize_url_filtering_log_summary,
        evidence_type="URL_FILTERING_LOG_SUMMARY", label="URL Filtering Log Summary",
        scopes=frozenset({"FIREWALL"}), call_kwargs=lambda d: {"nlogs": 1000},
        is_aggregate=True,
    ),
    _Resource(
        key="dns_threat_log_summary", method_name="get_dns_threat_logs",
        normalizer=schemas.normalize_dns_threat_log_summary,
        evidence_type="DNS_THREAT_LOG_SUMMARY", label="DNS Threat Log Summary",
        scopes=frozenset({"FIREWALL"}), call_kwargs=lambda d: {"nlogs": 1000, "query": _DNS_THREAT_QUERY},
        is_aggregate=True,
    ),
]

_RESOURCE_BY_KEY: Dict[str, _Resource] = {r.key: r for r in _RESOURCE_REGISTRY}


# ----------------------------------------------------------------------
# Config validation
# ----------------------------------------------------------------------

def _load_devices_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _validate_config(config: dict, collect_only: bool) -> None:
    """Fail fast on a structurally invalid devices.json instead of a
    mid-run KeyError that throws away already-collected evidence."""
    direct = config.get("direct_firewalls", [])
    panorama_cfg = config.get("panorama")
    panorama_managed = config.get("panorama_managed_firewalls", [])

    if not direct and not panorama_managed and not (panorama_cfg and panorama_cfg.get("device_groups")):
        raise ConfigError("devices config has no direct_firewalls, panorama_managed_firewalls, or panorama.device_groups -- nothing to collect")

    for fw in direct:
        if "name" not in fw or "host" not in fw:
            raise ConfigError(f"direct_firewalls entry missing required 'name'/'host': {fw}")

    if panorama_managed and not (panorama_cfg and panorama_cfg.get("host")):
        raise ConfigError("devices config lists panorama_managed_firewalls but no 'panorama.host' was supplied")

    for fw in panorama_managed:
        if "name" not in fw or "serial" not in fw:
            raise ConfigError(f"panorama_managed_firewalls entry missing required 'name'/'serial': {fw}")

    if panorama_cfg and panorama_cfg.get("device_groups") and "host" not in panorama_cfg:
        raise ConfigError("devices config has panorama.device_groups but no 'panorama.host' was supplied")

    if not collect_only:
        missing = [v for v in ("DRATA_API_KEY", "PAN_DRATA_CONNECTION_ID", "PAN_DRATA_RESOURCE_ID") if not os.environ.get(v)]
        if missing:
            raise ConfigError(f"missing required env vars for publishing (pass --collect-only to skip publish): {missing}")


# ----------------------------------------------------------------------
# Device context construction
# ----------------------------------------------------------------------

def _connector_for(host: str, username: str, password: str, verify_tls) -> PanFirewallConnector:
    auth = PanAuthClient(host=host, username=username, password=password, verify_tls=verify_tls)
    return PanFirewallConnector(host=host, auth=auth, verify_tls=verify_tls)


def _build_device_contexts(config: dict, username: str, password: str) -> List[DeviceContext]:
    contexts: List[DeviceContext] = []

    for fw_cfg in config.get("direct_firewalls", []):
        conn = _connector_for(fw_cfg["host"], username, password, fw_cfg.get("verify_tls", True))
        contexts.append(DeviceContext(
            id=fw_cfg["name"], hostname=fw_cfg["host"], scope="FIREWALL", managed_by="DIRECT",
            site=fw_cfg.get("site", "UNSPECIFIED"), vsys=fw_cfg.get("vsys", "vsys1"),
            connector=conn, license_connector=conn,
        ))

    panorama_cfg = config.get("panorama")
    panorama_conn: Optional[PanFirewallConnector] = None
    if panorama_cfg:
        panorama_conn = _connector_for(
            panorama_cfg["host"], username, password, panorama_cfg.get("verify_tls", True)
        )

    for fw_cfg in config.get("panorama_managed_firewalls", []):
        serial = fw_cfg["serial"]
        # License is always proxied through Panorama (confirmed to work via
        # target=<serial>, pan_api_research.md section 6) regardless of
        # whether a direct host is also configured below.
        license_conn = SimpleNamespace(get_license_info=lambda s=serial: panorama_conn.get_license_info(target=s))

        direct_conn = None
        if fw_cfg.get("host"):
            direct_conn = _connector_for(fw_cfg["host"], username, password, fw_cfg.get("verify_tls", True))
        else:
            logger.warning(
                "device=%s has no direct 'host' configured — profiles/rules/logs "
                "require direct firewall reachability per confirmed docs (REST "
                "panorama-pushed and XML log queries are not confirmed to proxy "
                "through Panorama); only license_info will be collected for this device.",
                fw_cfg["name"],
            )

        contexts.append(DeviceContext(
            id=fw_cfg["name"], hostname=fw_cfg.get("host") or f"panorama-proxy:{serial}",
            scope="FIREWALL", managed_by="PANORAMA", site=fw_cfg.get("site", "UNSPECIFIED"),
            vsys=fw_cfg.get("vsys", "vsys1"), connector=direct_conn, license_connector=license_conn,
        ))

    if panorama_conn:
        for dg_name in panorama_cfg.get("device_groups", []):
            contexts.append(DeviceContext(
                id=dg_name, hostname=panorama_cfg["host"], scope="DEVICE_GROUP", managed_by="PANORAMA",
                site=panorama_cfg.get("site", "UNSPECIFIED"), device_group=dg_name, connector=panorama_conn,
            ))

    return contexts


# ----------------------------------------------------------------------
# Collect (sequential; two-layer fault isolation; incremental writes)
# ----------------------------------------------------------------------

def _write_snapshot(output_path: str, collected_at: str, raw: dict, normalized: list) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({"collected_at": collected_at, "raw": raw, "normalized": normalized}, f, indent=2, default=str)


def _collect(device_contexts: List[DeviceContext], resources: List[_Resource], output_path: str, run_timestamp: str) -> dict:
    """
    Sequential (no concurrency) -- PANW's own guidance caps concurrent
    calls at ~5/device for management-plane performance, and with limited
    live-device validation this isn't the moment to add threading risk for
    a performance win nobody's asked for. Revisit only if a real deployment
    genuinely needs faster wall-clock time, and cap concurrency at that
    ~5/device guidance if so.

    Two-layer exception handling: each (device, resource) call is caught
    individually so one failing
    endpoint doesn't take down its siblings; the whole per-device loop is
    caught again so one dead device can't take down the run. Writes a
    snapshot to disk after every device so a mid-run crash doesn't lose
    already-collected evidence.
    """
    raw_results: dict = {}

    for device in device_contexts:
        device_results: dict = {}
        try:
            for resource in resources:
                if device.scope not in resource.scopes:
                    continue

                connector = getattr(device, resource.connector_attr)
                if connector is None:
                    device_results[resource.key] = {"error": "not collected: no direct host configured for this device"}
                    continue

                try:
                    kwargs = resource.call_kwargs(device)
                    raw = getattr(connector, resource.method_name)(**kwargs)
                    count = len(raw) if isinstance(raw, list) else 1
                    logger.info("call_ok device=%s key=%s records=%d", device.id, resource.key, count)
                    device_results[resource.key] = raw
                except Exception as exc:
                    logger.error("call_failed device=%s key=%s error=%s", device.id, resource.key, exc)
                    device_results[resource.key] = {"error": str(exc)}
        except Exception as exc:
            logger.error("device_failed device=%s error=%s", device.id, exc)
            device_results = {"error": str(exc)}

        raw_results[device.id] = device_results
        _write_snapshot(output_path, run_timestamp, raw_results, [])

    return raw_results


# ----------------------------------------------------------------------
# Normalize
# ----------------------------------------------------------------------

def _normalize(raw_results: dict, device_contexts: List[DeviceContext], resources: List[_Resource], run_timestamp: str) -> list:
    records: list = []
    devices_by_id = {d.id: d for d in device_contexts}

    for device_id, device_raw in raw_results.items():
        device = devices_by_id.get(device_id)
        if device is None or not isinstance(device_raw, dict) or set(device_raw.keys()) == {"error"}:
            continue

        for resource in resources:
            if device.scope not in resource.scopes:
                continue
            data = device_raw.get(resource.key)
            if data is None or (isinstance(data, dict) and "error" in data):
                continue

            if resource.is_aggregate:
                records.append(resource.normalizer(
                    data, device, run_timestamp, run_timestamp, run_timestamp, **resource.normalizer_kwargs
                ))
            else:
                for entry in data:
                    records.append(resource.normalizer(entry, device, run_timestamp, **resource.normalizer_kwargs))

    return records


# ----------------------------------------------------------------------
# Publish
# ----------------------------------------------------------------------

def _publish(records: list) -> None:
    DrataPublisher().publish(records)


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Palo Alto Networks compliance evidence collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--devices-config", required=True,
        help="Path to a JSON file describing the device inventory (see devices.example.json).",
    )
    parser.add_argument(
        "--output", default="pan_payload.json",
        help="JSON output file for collected + normalized data (default: pan_payload.json).",
    )
    parser.add_argument(
        "--resources", default=None,
        help=f"Comma-separated subset of resource keys to collect (default: all). Choices: {','.join(_RESOURCE_BY_KEY)}",
    )
    parser.add_argument(
        "--collect-only", action="store_true",
        help="Skip publishing to Drata; only write the local JSON output.",
    )
    args = parser.parse_args()

    username = os.environ.get("PAN_USERNAME")
    password = os.environ.get("PAN_PASSWORD")
    if not username or not password:
        logger.error("Missing required environment variables: PAN_USERNAME, PAN_PASSWORD")
        sys.exit(1)

    config = _load_devices_config(args.devices_config)

    try:
        _validate_config(config, collect_only=args.collect_only)
    except ConfigError as exc:
        logger.error("invalid devices config: %s", exc)
        sys.exit(1)

    if args.resources:
        requested = [k.strip() for k in args.resources.split(",")]
        unknown = [k for k in requested if k not in _RESOURCE_BY_KEY]
        if unknown:
            logger.error("unknown --resources key(s): %s (choices: %s)", unknown, ",".join(_RESOURCE_BY_KEY))
            sys.exit(1)
        resources = [_RESOURCE_BY_KEY[k] for k in requested]
    else:
        resources = _RESOURCE_REGISTRY

    device_contexts = _build_device_contexts(config, username, password)
    run_timestamp = datetime.now(timezone.utc).isoformat()

    raw_results = _collect(device_contexts, resources, args.output, run_timestamp)
    records = _normalize(raw_results, device_contexts, resources, run_timestamp)
    _write_snapshot(args.output, run_timestamp, raw_results, records)
    logger.info("payload_written path=%s records=%d", args.output, len(records))

    if args.collect_only:
        logger.info("collect_only set — skipping Drata publish")
    else:
        _publish(records)


if __name__ == "__main__":
    main()
