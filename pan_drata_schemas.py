"""
pan_drata_schemas.py
Normalizers that map raw PAN-OS/Panorama API records to the Drata evidence
schema, following the same connector -> normalizer -> publisher pattern
Drata's SA team uses for its other custom connections.

Every normalizer receives a raw record, a device context object (built by
pan_main.py's DeviceContext -- duck-typed here, not imported, to avoid a
pan_main.py <-> pan_drata_schemas.py import cycle) exposing:
    .id            string  -- stable device/device-group identifier
    .hostname      string  -- management hostname
    .site          string  -- free-form site/location label, e.g. "Site-A" | "Azure-<name>" | "UNSPECIFIED"
    .managed_by    string  -- "DIRECT" | "PANORAMA" (is this firewall itself Panorama-managed)
    .scope         string  -- "FIREWALL" | "DEVICE_GROUP" (what kind of object this record came from)
    .device_group  string | None
and a run_timestamp (ISO 8601 string, computed once per run so every record
in one run shares the same timestamp -- keeps normalizers pure/deterministic,
which matters given there is no live device to validate against; see
pan_api_research.md).

CORE FIELDS (guaranteed on every record):
    "id"            string  -- deterministic composite (f"{device.id}:{evidenceType}:{name}")
                               so re-runs upsert instead of duplicating
    "service"       string  -- "pan_firewall" | "panorama" (which surface answered the call --
                               device.scope == "DEVICE_GROUP" means Panorama answered for its
                               own device-group definitions; "FIREWALL" means a firewall did,
                               regardless of whether that firewall is itself Panorama-managed)
    "evidenceType"  string  -- FIREWALL_LICENSE | URL_FILTERING_PROFILE | DNS_SECURITY_PROFILE |
                               SECURITY_RULE | TRAFFIC_LOG_SUMMARY | URL_FILTERING_LOG_SUMMARY |
                               DNS_THREAT_LOG_SUMMARY
    "name"          string  -- human-readable label shown in the Drata UI
    "status"        string  -- see STATUS VOCABULARY below
    "timestamp"     string  -- run_timestamp, ISO 8601

DEVICE-TRACEABILITY FIELDS (always present, not optional -- PAN's fleet
fan-out makes this mandatory rather than incidental, unlike the Microsoft
schema's shared-*optional* fields):
    "deviceHostname" string
    "site"           string
    "managedBy"      string

STATUS VOCABULARY (subset of the Microsoft schema's enum actually used here):
    COMPLIANT     -- license not expired
    NONCOMPLIANT  -- license expired
    CONFIGURED    -- profile/log-summary exists (existence-is-evidence;
                     an empty result list is left to Drata's NO_RESPONSE
                     test signal rather than this module inventing one)
    ENABLED       -- security rule not disabled
    DISABLED      -- security rule disabled

Fields with a None value are omitted so Drata receives a clean sparse record
rather than one full of null values.

Drata SA Team
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Optional


def _build(**kwargs: Any) -> dict:
    """Construct a schema record, dropping any key whose value is None."""
    return {k: v for k, v in kwargs.items() if v is not None}


def _service_for(device: Any) -> str:
    return "panorama" if getattr(device, "scope", None) == "DEVICE_GROUP" else "pan_firewall"


def _device_fields(device: Any) -> dict:
    return {
        "deviceHostname": getattr(device, "hostname", None),
        "site": getattr(device, "site", None),
        "managedBy": getattr(device, "managed_by", None),
    }


def _member_list(node: Any) -> Optional[list]:
    """
    PAN REST 'member-list' fields come back as {"member": [...]} (confirmed
    in official REST examples). Also tolerates a bare list/string, since the
    REST JSON byte-shape of some nested fields (e.g. profile-setting.group)
    isn't confirmed against a live device -- a surprise shape must not
    crash normalization of the whole run.
    """
    if not node:
        return None
    members = node.get("member") if isinstance(node, dict) else node
    if isinstance(members, str):
        members = [members]
    return list(members) if members else None


def _as_list(node: Any) -> list:
    """PAN REST 'entry' collections are arrays; tolerate a lone object."""
    if not node:
        return []
    return node if isinstance(node, list) else [node]


def _location_id_part(entry: dict) -> str:
    """Every REST entry carries @location (vsys | shared | panorama-pushed |
    device-group). Folded into record ids so the same object name defined in
    two locations can't collide and overwrite itself in Drata."""
    location = entry.get("@location")
    return f"{location}:" if location else ""


def _norm_action(value: Any) -> str:
    """PAN docs write multi-word actions both ways ("reset client" in the
    traffic-log table, "reset-client" in syslog/XML) -- normalize."""
    return (value or "").strip().lower().replace(" ", "-")


# ── Licenses ──────────────────────────────────────────────────────────────────

def normalize_license(entry: dict, device: Any, run_timestamp: str) -> dict:
    """
    Source: PanFirewallConnector.get_license_info() -> XML type=op, request license info.
    status is COMPLIANT/NONCOMPLIANT off the now-fixed `expired` bool
    (pan_api_research.md section 2 confirms `expired` as literal "yes"/"no",
    converted to bool in pan_firewall.py).
    """
    feature = entry.get("feature")
    return _build(
        id=f"{device.id}:license:{feature}",
        service=_service_for(device),
        evidenceType="FIREWALL_LICENSE",
        name=feature,
        status="NONCOMPLIANT" if entry.get("expired") else "COMPLIANT",
        timestamp=run_timestamp,
        description=entry.get("description"),
        serial=entry.get("serial"),
        issuedDate=entry.get("issued"),
        expiresDate=entry.get("expires"),
        authcode=entry.get("authcode"),
        **_device_fields(device),
    )


# ── Security Profiles ─────────────────────────────────────────────────────────

def normalize_url_filtering_profile(entry: dict, device: Any, run_timestamp: str) -> dict:
    """
    Source: PanFirewallConnector.get_url_filtering_profiles() -> REST
    Objects/URLFilteringSecurityProfiles. CONFIGURED is existence-is-evidence;
    an empty profile list is left to Drata's NO_RESPONSE signal.
    """
    name = entry.get("@name")
    return _build(
        id=f"{device.id}:url_filtering_profile:{_location_id_part(entry)}{name}",
        service=_service_for(device),
        evidenceType="URL_FILTERING_PROFILE",
        name=name,
        status="CONFIGURED",
        timestamp=run_timestamp,
        location=entry.get("@location"),
        blockedCategories=_member_list(entry.get("block")),
        alertCategories=_member_list(entry.get("alert")),
        allowCategories=_member_list(entry.get("allow")),
        **_device_fields(device),
    )


def normalize_dns_security_profile(entry: dict, device: Any, run_timestamp: str) -> dict:
    """
    Source: PanFirewallConnector.get_dns_security_profiles() -> REST
    Objects/AntiSpywareSecurityProfiles. DNS Security lives inside the
    Anti-Spyware profile's botnet-domains/dns-security-categories block
    (pan_api_research.md section 3, confirmed via Iron Skillet source).
    Field name is `log-level` -- NOT `log-severity` (a different, unrelated
    field on the URL Filtering profile's credential-enforcement block --
    confirmed naming trap, don't conflate the two).
    """
    name = entry.get("@name")
    categories = _as_list(
        (entry.get("botnet-domains") or {}).get("dns-security-categories", {}).get("entry")
    )
    dns_security_categories = [
        _build(category=c.get("@name"), action=c.get("action"), logLevel=c.get("log-level"))
        for c in categories
    ]
    return _build(
        id=f"{device.id}:dns_security_profile:{_location_id_part(entry)}{name}",
        service=_service_for(device),
        evidenceType="DNS_SECURITY_PROFILE",
        name=name,
        status="CONFIGURED",
        timestamp=run_timestamp,
        location=entry.get("@location"),
        dnsSecurityCategories=dns_security_categories or None,
        enabledCategoryCount=len(dns_security_categories) or None,
        **_device_fields(device),
    )


# ── Security Policy Rules ─────────────────────────────────────────────────────

def normalize_security_rule(entry: dict, device: Any, run_timestamp: str, rule_scope: str) -> dict:
    """
    Source: get_security_rules() (rule_scope="LOCAL"), get_security_pre_rules()
    (rule_scope="PRE_RULE"), get_security_post_rules() (rule_scope="POST_RULE").
    Pre/Post/Local rules collapse into one evidenceType with a `ruleScope`
    field -- fewer evidence types to map against Drata control requirements.

    status is ENABLED/DISABLED off the rule's `disabled` attribute (more
    informative than a blanket CONFIGURED, since PAN rule objects carry a
    real enabled/disabled state) -- NO_RESPONSE still fires naturally at
    Drata if the rule list comes back empty.

    Profile attachment: confirmed at the XML/config-tree level as
    `profile-setting.group` (named Security Profile Group) or
    `profile-setting.profiles.<category>` (individually-attached profiles)
    -- pan_api_research.md section 4. The REST JSON byte-shape of this field
    is an open gap in that research; this normalizer's handling of the
    `{"group": {"member": [...]}}` / `{"profiles": {"<type>": {"member": [...]}}}`
    shape is a best-effort construction pending live-device confirmation.
    """
    name = entry.get("@name")
    profile_setting = entry.get("profile-setting") or {}
    security_profiles = {
        category: _member_list(members)
        for category, members in (profile_setting.get("profiles") or {}).items()
    }
    return _build(
        id=f"{device.id}:security_rule:{rule_scope}:{_location_id_part(entry)}{name}",
        service=_service_for(device),
        evidenceType="SECURITY_RULE",
        name=name,
        status="DISABLED" if entry.get("disabled") == "yes" else "ENABLED",
        timestamp=run_timestamp,
        ruleScope=rule_scope,
        location=entry.get("@location"),
        action=entry.get("action"),
        applications=_member_list(entry.get("application")),
        sourceZones=_member_list(entry.get("from")),
        destZones=_member_list(entry.get("to")),
        securityProfileGroup=_member_list(profile_setting.get("group")),
        securityProfiles=security_profiles or None,
        deviceGroup=getattr(device, "device_group", None),
        **_device_fields(device),
    )


# ── Log Summaries (aggregated -- one record per device per log type, refreshed every run) ─────
#
# Each summary covers the N most recent matching log entries returned by the
# firewall (N = sample_limit, see pan_main._LOG_SAMPLE_SIZE), NOT a fixed time
# window. windowStart/windowEnd are the earliest/latest `receive_time` actually
# present in that sample (device-local time, as PAN returns it), so they
# describe the data honestly; logLimitReached says whether the sample was capped
# (totalLogCount is then a floor, not a true count).
#
# The record id is stable per device + log type, so each run upserts the same
# record instead of accumulating a new one every day.

def _log_summary(
    entries: list,
    device: Any,
    run_timestamp: str,
    evidence_type: str,
    label: str,
    id_prefix: str,
    affected_count: int,
    breakdown_field: Optional[str],
    breakdown_key: Optional[str],
    sample_limit: Optional[int],
) -> dict:
    breakdown = None
    if breakdown_field:
        breakdown = dict(Counter(e.get(breakdown_field) or "unknown" for e in entries)) or None
    times = sorted(t for t in (e.get("receive_time") for e in entries) if t)
    return _build(
        id=f"{device.id}:{id_prefix}",
        service=_service_for(device),
        evidenceType=evidence_type,
        name=f"{label} - {getattr(device, 'hostname', device.id)}",
        status="CONFIGURED",
        timestamp=run_timestamp,
        totalLogCount=len(entries),
        affectedCount=affected_count,
        windowStart=times[0] if times else None,
        windowEnd=times[-1] if times else None,
        logLimitReached=(len(entries) >= sample_limit) if sample_limit else None,
        **({breakdown_key: breakdown} if breakdown_key else {}),
        **_device_fields(device),
    )


def _non_allow(entries: list) -> int:
    return sum(1 for e in entries if _norm_action(e.get("action")) not in ("", "allow"))


def normalize_traffic_log_summary(entries: list, device: Any, run_timestamp: str, sample_limit: Optional[int] = None) -> dict:
    """
    Source: PanFirewallConnector.get_traffic_logs(). Always emits exactly
    one record per device per run, even at zero count, so "no denied
    traffic occurred" is distinguishable from "collector didn't run".

    affectedCount = entries whose `action` is anything other than allow.
    PAN's documented traffic-log actions are allow, deny, drop, drop ICMP,
    reset client, reset server, reset both -- everything except allow is an
    enforcement action (docs.paloaltonetworks.com/ngfw/administration/
    monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields).
    """
    return _log_summary(
        entries, device, run_timestamp,
        evidence_type="TRAFFIC_LOG_SUMMARY", label="Traffic Log Summary",
        id_prefix="traffic", affected_count=_non_allow(entries),
        breakdown_field="action", breakdown_key="actionBreakdown",
        sample_limit=sample_limit,
    )


def normalize_url_filtering_log_summary(entries: list, device: Any, run_timestamp: str, sample_limit: Optional[int] = None) -> dict:
    """
    Source: PanFirewallConnector.get_url_filtering_logs().
    affectedCount = entries whose `action` is anything other than allow
    (alert, block-url, block-continue, continue, block-override, override,
    override-lockout, deny, drop, reset-*). `category` on a URL log entry is
    the URL category, so the breakdown by `category` is correct here.
    """
    return _log_summary(
        entries, device, run_timestamp,
        evidence_type="URL_FILTERING_LOG_SUMMARY", label="URL Filtering Log Summary",
        id_prefix="urlFiltering", affected_count=_non_allow(entries),
        breakdown_field="category", breakdown_key="categoryBreakdown",
        sample_limit=sample_limit,
    )


def normalize_dns_threat_log_summary(entries: list, device: Any, run_timestamp: str, sample_limit: Optional[int] = None) -> dict:
    """
    Source: PanFirewallConnector.get_dns_threat_logs() -- Threat log filtered
    on `category-of-threatid`. Every entry returned by a correctly-filtered
    call is itself a DNS threat match, so affectedCount == totalLogCount.

    Breakdown is by `thr_category` ("Threat Category", which carries values
    like dns-c2). NOT `category`: on a threat log entry `category` is the URL
    category (or "any" for non-URL subtypes), per PAN's threat-log field
    table -- grouping by it would report every DNS threat as "any".
    """
    return _log_summary(
        entries, device, run_timestamp,
        evidence_type="DNS_THREAT_LOG_SUMMARY", label="DNS Threat Log Summary",
        id_prefix="dnsThreat", affected_count=len(entries),
        breakdown_field="thr_category", breakdown_key="categoryBreakdown",
        sample_limit=sample_limit,
    )
