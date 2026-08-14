# PAN-OS / Panorama API — Grounded Technical Findings

Compiled from official Palo Alto Networks documentation (docs.paloaltonetworks.com), pan.dev, and — for the cases where no test device or Palo Alto support access is available — cross-validated against the source code of widely-used open-source PAN-OS clients: `github.com/PaloAltoNetworks/pan-os-python` (official SDK), `github.com/PaloAltoNetworks/pango` + `terraform-provider-panos` (official Go SDK/provider), `github.com/PaloAltoNetworks/pan-os-ansible`, `github.com/PaloAltoNetworks/ironskillet-components` (official config templates), and `github.com/kevinsteves/pan-python` (long-standing community reference client, written by an ex-PANW engineer, used internally by pan-os-python). Target environment: PAN-OS 11.1.x and 11.2.x.

**Confidence tiers used below:**
- **CONFIRMED (official docs)** — stated verbatim on docs.paloaltonetworks.com / pan.dev.
- **CONFIRMED (SDK source)** — not in prose docs, but the exact wire format is read directly from actively-maintained client source code that real users run against real devices daily. Treated as high confidence — these libraries would break immediately if wrong.
- **Open gap** — genuinely unconfirmed by any public source; needs a live device or Palo Alto support.

Every claim below was backed by a structured research pass across 10 topics with full citations/evidence, condensed here into one reference document.

**Structural note on Palo Alto's doc site:** version-pinned API documentation (`docs.paloaltonetworks.com/pan-os/11-1/...`) exists through the 11.1 branch; there is no separate `pan-os/11-2/...` API tree. PAN-OS 11.1+ API/Admin-Role content has been consolidated into a version-agnostic tree (`docs.paloaltonetworks.com/ngfw/api/...`), whose own version-applicability list explicitly includes 11.1 and 11.2. No behavioral divergence between 11.1.13 and 11.2.10-H3 was found or claimed anywhere in official material for any capability below.

---

## 1. Authentication

- Both APIs require an API key via `POST /api/?type=keygen` with `user=`/`password=` form-encoded body. **CONFIRMED (official docs + SDK source, byte-identical):** the success response is `<response status="success"><result><key>...</key></result></response>` — i.e. the key is literally at `./result/key`. Two independent sources agree: the official generate-api-key doc page, and pan-python's `xapi.py` keygen() parser (`root.find('result').find('key')`). *(docs.paloaltonetworks.com/ngfw/api/api-authentication-and-security/generate-api-key; github.com/kevinsteves/pan-python/blob/master/lib/pan/xapi.py)*
- **XML API**: key can be supplied as `key=<apikey>` query parameter OR `X-PAN-KEY:` header. **REST API**: only `X-PAN-KEY` header is documented.
- API keys **do not expire by default** (Lifetime = 0). *(docs.paloaltonetworks.com/.../configure-api-key-lifetime)*
- **CONFIRMED (SDK source + official KB):** generating an additional key for the same admin does **not** invalidate previously-issued keys — multiple keys coexist validly. Keys are only invalidated by: (a) changing that admin's password, (b) "Expire all API Keys," (c) the configured Lifetime elapsing, or (d) enabling cert-based key encryption. *(knowledgebase.paloaltonetworks.com KCS kA10g000000CmesCAC; corroborated by pan-python having zero locking around its api_key cache — it doesn't need any, because concurrent keygen calls are all independently valid)*. A contradictory claim ("generating a new key kills existing sessions") surfaced in general web search but could not be traced to any locatable primary source and directly conflicts with the two sources above — treated as search-synthesis noise, not fact.
- **CONFIRMED (official KB):** Palo Alto's own best-practice guidance is to **limit concurrent API calls (of any kind) to 5** per device, purely for management-plane web-server performance — a soft guideline, not a hard-enforced limit. *(knowledgebase.paloaltonetworks.com KCS kA14u000000wkiFCAQ)* — **the prototype currently has no concurrency cap anywhere; worth adding if collection is ever parallelized.**
- **Open gap**: no single official sentence states a key generated via keygen is valid for both XML and REST calls interchangeably — structurally very likely (one shared keygen endpoint, identical X-PAN-KEY mechanism referenced on both API surfaces' pages) but not stated as one fact. Low-cost to close with a live test once a device exists.
- **Open gap**: no source states whether PAN-OS enforces any rate limit specifically on `type=keygen` distinct from the general 5-concurrent-calls guidance.

---

## 2. License Status (URL Filtering, DNS Security)

- **Confirmed: XML API only** via `type=op`, CLI command `request license info`. REST has no license resource.
- **UPGRADED FROM "unconfirmed, pattern-guessed" TO CONFIRMED (SDK source, cross-validated by two independent libraries + a real captured device response):**
  - Request body: `<request><license><info/></license></request>` — this is exactly what `pan-os-python`'s `request_license_info()` sends (it calls `self.op("request license info")`, and PAN-OS-op-command text-to-XML conversion nests tokens word-by-word). Independently, `pan-python`'s own text-to-XML converter produces the identical nesting.
  - Response xpath: `./result/licenses/entry`, confirmed identically by `pan-os-python`'s `_format_result_as_license_list()` (`result.findall("./result/licenses/entry")`).
  - **Real captured example against a live PAN-OS VM-50** (from `pan-python`'s own docs, `doc/panlicapi.rst`): `{"licenses": {"entry": [{"authcode": null, "description": "Standard VM-50", "expired": false, "expires": "Never", "feature": "PA-VM", "issued": "March 24, 2017", "serial": "015351000001360"}]}}` — this is a real device response, not just SDK-side assumption.
  - **Fields per entry**: `feature`, `description`, `serial`, `issued`, `expires`, `expired`, and **`authcode`** — the prototype's current parser is missing `authcode` (7th field). `expired` is the literal string `"yes"`/`"no"`, not a native boolean — `pan-os-python` explicitly does `.text == "yes"` to convert it; do the same rather than passing the raw string through.
  - *(github.com/PaloAltoNetworks/pan-os-python/blob/develop/panos/base.py; github.com/PaloAltoNetworks/pan-os-python/blob/develop/panos/__init__.py; github.com/kevinsteves/pan-python/blob/master/doc/panlicapi.rst)*
- Still true: **no official docs.paloaltonetworks.com/pan.dev page publishes this literal XML anywhere** — Palo Alto's documented way to get it is `debug cli on` on a live box. The confirmation above comes from source-code + real-device-output cross-validation, which is strong but not a first-party doc citation. If 100% official-doc certainty is ever required, still worth doing `debug cli on` once a device exists.
- **Open gap, unchanged:** the exact `Feature` string for DNS Security's subscription line is still not confirmed by any sample found.

---

## 3. Security Profiles (URL Filtering, DNS Security)

- **Confirmed: REST API**, `Objects/URLFilteringSecurityProfiles` and `Objects/AntiSpywareSecurityProfiles` (`v11.0` version segment).
- **DNS Security lives inside the Anti-Spyware profile** (confirmed), but its exact internal shape was previously a total unknown. **NOW CONFIRMED (official PANW config-template source, Iron Skillet, PAN-OS 11.0 — same generation as the 11.1.x/11.2.x target fleet):**
  - Structure: `entry > botnet-domains > { lists (EDL/botnet entries, each with action + packet-capture), dns-security-categories (entry-array of 9 categories, each with log-level + action + packet-capture), sinkhole ({ipv4-address, ipv6-address}) }`
  - The 9 DNS category entry names: `pan-dns-sec-benign, pan-dns-sec-cc, pan-dns-sec-ddns, pan-dns-sec-grayware, pan-dns-sec-malware, pan-dns-sec-parked, pan-dns-sec-phishing, pan-dns-sec-proxy, pan-dns-sec-recent`.
  - **Naming trap confirmed — do not get this wrong:** the WebUI label is "Log Severity" but the actual tag is `<log-level>`, NOT `<log-severity>` (that tag genuinely exists elsewhere, in the URL Filtering profile's credential-enforcement block, for a different field — don't confuse the two).
  - Confirmed action vocabulary: `default`, `sinkhole` (from real config); WebUI also documents `alert`/`allow`/`block` as selectable actions; `sinkhole` is PAN-OS's default action for Palo Alto DNS signatures.
  - Same source also confirms **URL Filtering profile** shape: per-action category-membership lists (`<alert><member>category</member></alert>`, `<block>...`), plus `<credential-enforcement><mode>...<log-severity>...<block>/<alert>`, plus booleans `log-http-hdr-user-agent`, `log-http-hdr-referer`, `log-http-hdr-xff`.
  - *(raw.githubusercontent.com/PaloAltoNetworks/ironskillet-components/main/panos_v11.0/panorama/panorama_profiles_spyware_11_0.skillet.yaml and .../panorama_profiles_url_filtering_11_0.skillet.yaml)*
  - **Correction to a prior assumption:** `pan-os-python`'s `objects.py` does **NOT** model these profiles at all — no `AntiSpywareProfile`/`URLFilteringProfile` class exists in that SDK at any checked revision (confirmed by direct source grep + readthedocs class list). It only models `SecurityProfileGroup` (the group construct referencing profile names as strings). Don't look to that SDK for this — the Iron Skillet templates are the source here.
- **Remaining open gap:** the exact **REST JSON encoding** of self-closing XML "choice" elements (e.g. `<action><sinkhole/></action>`) is still not seen in any official JSON example for this specific object — could render as `{"sinkhole":{}}`, `{"sinkhole":null}`, or something else. Inferred by analogy to the general REST convention, not confirmed for this object. Also: Iron Skillet has no PAN-OS 11.1/11.2 branch (only 10.0–10.2, 11.0), so one minor-version extrapolation gap remains even after this research (10.1→11.0 was stable, supporting low risk).
- Palo Alto states the authoritative, complete field list lives on-device at `/restapi-doc` — still the only way to fully close the JSON-encoding gap above.

---

## 4. Security Policy Rules (rulebase, applications, profile attachments)

- REST resource paths confirmed unchanged: `Policies/SecurityRules` (`location=vsys` or `location=panorama-pushed`, firewall-only), `Policies/SecurityPreRules`/`Policies/SecurityPostRules` (`location=device-group`, Panorama-only).
- **`SecurityPreRules` is CONFIRMED by an official worked example** (full JSON body). **`SecurityPostRules` is only medium-confidence** — not found in any official docs.paloaltonetworks.com or pan.dev page fetched; only backed by a LIVEcommunity forum thread title/snippet plus product-level Pre/Post-Rule symmetry. Worth a first live call to confirm before treating as load-bearing.
- **UPGRADED FROM "not confirmed by any official example" TO CONFIRMED (SDK source, independently corroborated by TWO separately-maintained official SDKs):**
  - The field is `profile-setting`, with two mutually-used children:
    - `profile-setting/group` — a member-list referencing one named Security Profile Group
    - `profile-setting/profiles/<category>` — member-lists per individually-attached profile type: `virus, spyware, vulnerability, url-filtering, file-blocking, wildfire-analysis, data-filtering` (plus newer `gtp`, `sctp` in the more current Go SDK — PAN-OS 10.2+/11.x mobile-network profiles)
  - Confirmed identically in `pan-os-python` (`panos/policies.py`, class `SecurityRule._setup()`) and in `pango` (`policies/rules/security/entry.go`) — the same Go module version that `terraform-provider-panos`'s current main branch depends on.
  - **DNS Security is confirmed NOT a rule-level field** in either SDK — reinforces that it only lives inside the Anti-Spyware profile object (section 3), never attached directly to a rule.
  - *(github.com/PaloAltoNetworks/pan-os-python/blob/master/panos/policies.py; github.com/PaloAltoNetworks/pango/blob/main/policies/rules/security/entry.go)*
- **Still open:** the exact **REST JSON** byte-shape of `profile-setting` (as opposed to the now-confirmed XML/config-tree shape) has never been seen in an official worked REST example. Very likely `{"profile-setting": {"group": {"member": [...]}}}` or `{"profiles": {"virus": {"member": [...]}, ...}}` by analogy to every other confirmed list field's `{"tag": {"member": [...]}}` convention — but not literally observed. Needs a live GET on a rule that actually has a profile attached, or the device's own `/restapi-doc`.
- **New finding, useful for any future write path:** PAN-OS REST `PUT` is a full-replace operation, not a patch — official guidance is GET the rule, copy the whole body, modify, then PUT the whole thing back. A partial PUT throws 400. Not relevant to this GET-only prototype today, but flag it before ever adding a write path.

---

## 5. Traffic / URL Filtering / DNS Security Logs

- **Confirmed async job flow, xpaths now nailed down with an exact official worked example (previously only inferred):**
  1. Submit → job ID at `./result/job` — verbatim: `<response status="success" code="19"><result><msg><line>query job enqueued with jobid 18</line></msg><job>18</job></result></response>`
  2. Poll `type=log&action=get&job-id=<id>` until finished
  3. Completed entries at `./result/log/logs/entry` — verbatim official example: `<log><logs count="20" progress="100"><entry logid="..."><domain>1</domain><receive_time>...</receive_time>...<type>TRAFFIC</type><subtype>start</subtype>...</entry>`
  *(docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/retrieve-logs — note Palo Alto's own published HTML has two typos in this exact block, confirmed present on the live page, not a research artifact)*
- **IMPORTANT CORRECTNESS FINDING — recommend fixing this in code:** official docs describe completion only in prose ("the `<log>` node is not present when the job status is still pending"), which is what the prototype currently checks. But the reference client (`pan-python`, used internally by the official SDK) does **not** rely on that heuristic at all — it polls the *same* endpoint and checks `./result/job/status` for the literal text `"FIN"`. This matters: **a job that legitimately matches zero log entries could plausibly finish (`status=FIN`) without ever populating a `<log>` node**, which would make the current "is `<log>` present" heuristic **poll forever on an empty result set**. Recommend checking `result/job/status == "FIN"` as the primary completion signal, falling back to the `<log>`-presence heuristic only if `status` is absent. *(github.com/kevinsteves/pan-python/blob/master/lib/pan/xapi.py, lines ~1154-1159)*
- **DNS Security log filtering — the prototype's candidate filter was WRONG; here's the confirmed correct one:**
  - The Threat log's `Subtype` field does **not** have a `dns` value. Its full documented enumeration: `data, file, flood, packet, scan, spyware, url, ml-virus, virus, vulnerability, wildfire, wildfire-virus`. **Discard any `subtype eq dns` filter.**
  - **CONFIRMED correct field:** `category-of-threatid`, with documented example values `dns-c2`, `adns-hijacking`, and others referenced as existing (`ddns`, `parked`, `malware`) but not exhaustively enumerated anywhere. Example filter: `query=(category-of-threatid eq dns-c2)`.
  - The XML API's `query=` parameter is officially documented as using "similar" syntax to the Monitor tab's GUI log filter — this is the link that lets the GUI-documented `category-of-threatid` filter carry over to the API, though no single official page shows both combined in one worked `type=log` example (inferred by combining two separately-confirmed official statements).
  - *(docs.paloaltonetworks.com/ngfw/administration/monitoring/.../threat-log-fields; docs.paloaltonetworks.com/dns-security/administration/monitor-dns-security/view-dns-security-logs)*
- **Forward-looking, not relevant to an 11.1.x/11.2.x fleet:** PAN-OS 12.1+ adds a real dedicated DNS Security log type (must be explicitly enabled; forwarding-profile string is `dns-security`). Worth adopting once upgraded past 11.2 — would eliminate the Threat-log-filtering workaround entirely.
- **`target=` proxying for logs — evidence now points more strongly toward "does not work," not just "silent on it":**
  - `pan-python`'s `log()` method **never** sets `target=`/`self.serial` on either the submit or poll request — unlike literally every other request type (op, config, commit, export, report, user_id), which all explicitly check `if self.serial is not None: query['target'] = self.serial`.
  - Palo Alto's own Cortex XSOAR PAN-OS integration doc states this explicitly: *"The target argument is supported only in operational type commands... you cannot use it with commit, logs, or PCAP commands."*
  - This is convergent SDK-source + official-integration-doc evidence, not a single official-docs sentence on the Retrieve-Logs page itself (that page stays silent on `target=`) — so treat as **strong evidence, not fully closed** until tested live. **Current prototype code already does the right thing** — it never passes `target=` to any log call, and requires a direct `host` for log/profile/rule collection against Panorama-managed firewalls. Keep that design.

---

## 6. Panorama Proxying & Log Aggregation

- **Confirmed for `type=op` and `type=config` (get/show):** `target=<serial>` proxies through Panorama to a managed firewall. Reinforced by SDK source: `pan-python`'s shared `__type_config()` method applies `target=` identically regardless of action (show/get/set/edit/delete/rename/clone/move/override), and the official `pan-os-python` SDK's `Firewall.generate_xapi()` builds every proxied call (op, config, commit, export, report, user-id) through Panorama with `target=<serial>` automatically when a `Firewall` object has a serial but no direct hostname.
- **`target=` does NOT work for `type=log`** — see section 5. Also not confirmed either way for `type=export` or any REST endpoint (no source, official or community, shows anyone trying `target=` against REST at all).
- **Confirmed, with exact citation:** "Each firewall stores its log files locally by default and cannot display the logs that reside on other firewalls." Centralized visibility on Panorama requires explicit configuration: (1) create a Log Forwarding profile for the relevant log types, (2) assign it to Security/Authentication/DoS Protection rules and network zones. **Not automatic.** *(docs.paloaltonetworks.com/panorama/administration/manage-log-collection/configure-log-forwarding-to-panorama)*
- **Open, and operationally important:** whether your Panorama-managed firewalls actually have this forwarding configured is a live-environment/config-review question, not resolvable from public docs — **check this directly**, since it determines whether querying Panorama's own hostname for logs would return anything at all for those firewalls, independent of the `target=` question.
- REST API still cannot proxy through Panorama — Panorama's REST surface only exposes `shared`/`device-group` (intended push state), never a specific firewall's actual applied state.

---

## 7. Least-Privilege / Read-Only Service Account

- **XML API tab: Enable/Disable only, confirmed at the schema level, not just the GUI level.** The official Go SDK (`pango`, underlying the official Terraform provider) models the XML API permission block as one flat `*string` field per category with no nested read/write children (`RoleDeviceXmlapi.Config *string`) — structurally proving there's no read-only sub-state to select, not just a UI limitation. **Web UI and REST API tabs both genuinely support Enable / Read Only / Disable.**
- **UPGRADED — current, complete XML API category list (was previously only "three explicitly named in prose"):** `commit, config, export, import, iot, log, op, report, user-id` (9 fields, confirmed via `pango`'s struct definition). Note `iot` doesn't appear in older enumeration docs — likely a newer addition; worth a live-version check against your specific PAN-OS version since it postdates some older reference material.
- **New, useful finding — REST API RBAC is more granular than previously documented:** it's modeled **per individual object/rule type**, not just broad Objects/Policies categories. The `pango` schema has 37 independent fields under Objects (including `AntiSpywareSecurityProfiles`, `UrlFilteringSecurityProfiles`) and 11 under Policies (including `SecurityRules`) — each settable to Read Only independently. **Practical upgrade to the recommendation below:** scope REST Read-Only to exactly `Policies.SecurityRules`, `Objects.UrlFilteringSecurityProfiles`, `Objects.AntiSpywareSecurityProfiles` and leave everything else (NAT rules, addresses, network objects, etc.) Disabled, rather than a vaguer "relevant categories."
- **New finding, worth evaluating as an alternative:** a genuinely platform-enforced read-only XML API mode **does** exist — but only via the built-in dynamic role **"Superuser (read-only)"** ("enables the XML API in a read-only state"), not via any custom Admin Role Profile. Trade-off: it grants read access to the **entire box**, not scoped to just License/Log/Config-get — a breadth-vs-enforcement tradeoff worth a conscious decision. **Open gap:** Panorama's own "Superuser (read-only)" description omits the explicit XML-API-readonly phrasing the firewall page states — unclear if that's a documentation gap or an actual behavioral difference; needs live Panorama confirmation.
- **Updated recommended account configuration:**
  - XML API tab: enable only **Report, Log, Config** (needed for license-info op, log queries, and config-get fallback); leave Commit/Export/Import/IoT/User-ID disabled. "Config" still technically permits write actions too — enforcement of read-only-in-practice must come from the integration code only ever calling `get`/`show`/`report`/`log` (a code-discipline promise, not a platform control — the current code does honor this, no `set`/`edit`/`delete` calls exist anywhere in it).
  - REST API tab: set **`Policies.SecurityRules`, `Objects.UrlFilteringSecurityProfiles`, `Objects.AntiSpywareSecurityProfiles`** individually to Read Only; leave every other REST object/rule type Disabled.
  - Consider "Superuser (read-only)" as an alternative if the broader read scope is acceptable — it's the only *platform-enforced* read-only guarantee found for the XML API specifically.
  - Dedicated, non-shared admin account (unchanged, documented best practice).
- **Still open:** the literal enum string PAN-OS expects for a REST field's "Read Only" state (e.g. `"read-only"` vs `"readonly"`) isn't visible anywhere public — the SDK models it as an untyped string with device-side-only validation. Also open: whether "Read Only" actually blocks POST/PUT/DELETE at the HTTP layer (403/405) vs. just hiding UI controls — no source states this in exact wire terms.

---

## 8. Rate Limiting, Retries, and Concurrency *(new section — this was a completely unaddressed gap before)*

- **CONFIRMED (official docs):** limit concurrent API calls to ~5 per device (same guidance cited in section 1) — the one real, citable piece of Palo Alto rate-limit-adjacent guidance that exists. *(docs.paloaltonetworks.com/ngfw/api/get-started-with-the-pan-os-rest-api)*
- **CONFIRMED (official docs, by absence):** the official PAN-OS REST API Error Codes reference (codes 1–16) has **no entry for HTTP 429 and no mention of a `Retry-After` header anywhere** — verified by direct fetch, not summary.
- **CONFIRMED (exhaustive OSS source audit — this closes a real gap in the prototype's design assumptions):** **none** of the following implement or even attempt to parse an HTTP 429 / `Retry-After` response from a PAN-OS device: `pan-os-python` (0 matches for "429"/"retry"/"backoff" in a repo-wide code search), `pan-python` (no retry loop at all — `URLError`/`ssl.CertificateError` are terminal), `pango`/`terraform-provider-panos` (plain `http.Client`, no retry wrapper — the `go-retryablehttp` dependency in `go.mod` is transitive/unused, not actually wired up), `pan-os-ansible` (only retries the initial connection/auth, not mid-operation responses).
- **Contrast, for context:** Palo Alto's *other* products (Threat Vault API, Prisma Cloud CSPM) **do** document real HTTP 429 + rate-limit headers — proving this silence is specific to the PAN-OS/Panorama device-management API, not a general Palo Alto documentation gap.
- **Bottom line: `pan_base.py`'s retry logic (429+`Retry-After`, 5xx exponential backoff) is original, speculative defensive code — not a confirmed PAN-OS behavior, and not modeled on any known integration's practice.** It's harmless to keep (costs nothing if PAN-OS never sends 429) — just don't mistake it for a validated pattern. **Add the one real confirmed guidance** (a client-side concurrency cap of ~5) as an actual semaphore if this connector is ever parallelized, since nothing currently caps concurrency at all.
- **Open gap:** whether PAN-OS ever returns 429 (or any other explicit rate-limit signal) under real load remains genuinely unknown — no official or community source confirms or denies it. Needs a live device under load to settle.
- **Open gap:** no official recommended job-status polling interval exists beyond "poll until FIN" — `pan-python`'s own internal default (0.5s) and this project's default (3.0s) are both unvalidated client choices, not Palo Alto guidance.

---

## 9. TLS Certificate Validation Against Internal-CA-Signed Devices *(new section)*

- Enterprise firewalls typically present certs signed by an internal/enterprise CA, not a public CA — supporting only `verify_tls: true/false`, with `false` disabling verification entirely (no partial option), is a real security gap worth avoiding.
- **CONFIRMED (requests' own official docs):** `requests`' `verify` parameter natively accepts a **string path** to a CA bundle file (or a hashed cert directory), not just a bool — and can also be set globally via the `REQUESTS_CA_BUNDLE` env var. This is a zero-risk, already-supported-by-the-library fix.
- **CONFIRMED (SDK source, useful as a reference pattern):** `pan-python`'s CLI (`panxapi.py`) implements exactly this for its own users via `--cafile`/`--capath` flags: builds an `ssl.SSLContext(CERT_REQUIRED, check_hostname=True)`, calls `load_verify_locations(cafile=..., capath=...)`, passes it in. This is the reference shape for "validate against a specific internal CA without disabling verification."
- **Notable negative finding:** `pan-os-python`, `pan-os-ansible`, and `terraform-provider-panos`/`pango` all provide **only a boolean skip-verify flag** — none of them expose any custom-CA-bundle mechanism at all. A `pan-os-python` maintainer confirmed on GitHub (issue #120) that the library "does not check certificates by default" with no supported way to point it at a custom CA. **This means there's no ready-made PAN-OS-specific requests snippet to copy — the fix has to be adapted from `pan-python`'s `ssl_context` pattern and `requests`' own generic string-path support**, since this prototype (unlike any of the OSS tools surveyed) is actually built on `requests`.
- **Recommended code change (low-risk, ready to implement without a live device):**
  1. Change `verify_tls: bool` type hints to `Union[bool, str]` in `pan_auth.py`, `pan_base.py`, `pan_main.py` — no logic change needed, since `requests` already handles a string path correctly when passed straight through as `verify=`.
  2. Document in the devices-config schema that `verify_tls` may be `true`, `false`, or a filesystem path to a PEM CA bundle, e.g. `"verify_tls": "/etc/pan/internal-ca.pem"`.
  3. Zero-code fallback: operators can instead set `REQUESTS_CA_BUNDLE` env var and leave `verify_tls: true` — `requests` will consult it automatically.
- Official PAN-OS docs recommend replacing the management interface's self-signed cert with an enterprise-CA-issued one specifically so client systems already trust it — worth checking with your PKI team whether that's already done, since it changes whether a CA-bundle path is even needed yet.
- **Open gap:** whether a given fleet's management certs are self-signed or already enterprise-CA-issued is unknown without live access — determines whether this fix is needed immediately or is prep-work for later.

---

## Summary: API Surface Decision Matrix

| Data needed | API surface | Why |
|---|---|---|
| License/subscription status | XML API (`type=op`) | REST has no license resource at all |
| URL Filtering / Anti-Spyware (DNS Security) profiles | REST API (`Objects/...SecurityProfiles`) | Documented, JSON-native, supports real per-object-type Read-Only RBAC |
| Security policy rules (incl. applications, profile attachments) | REST API (`Policies/SecurityRules` / `SecurityPreRules` / `SecurityPostRules`) | Same as above |
| Traffic / URL Filtering logs | XML API (`type=log`) | REST has zero log capability, confirmed |
| DNS Security activity | XML API (`type=log&log-type=threat`, `query=(category-of-threatid eq ...)`) | No dedicated DNS log-type exists pre-12.1; confirmed correct filter field (not `subtype`) |

This is not an arbitrary XML-vs-REST choice — it's the documented capability boundary. Neither API alone covers everything needed.

## Items That Must Be Confirmed Against a Live Firewall Before Production Use

*(Updated — items 1–5 moved from "unconfirmed guess" to "confirmed via SDK/config-template source, pending final live-device sign-off"; items 6–7 unchanged; new items 8–12 added by this research pass.)*

1. ~~Exact XML request body for `request license info`~~ — now confirmed via `pan-os-python`/`pan-python` source + real captured VM-50 example. Live-device run still recommended as final sign-off.
2. Exact `Feature` string for the DNS Security subscription line in license output — **still genuinely unconfirmed**, no source found.
3. Exact JSON field name(s) for DNS-Security settings inside the `AntiSpywareSecurityProfiles` REST response — XML/config-tree shape now confirmed (section 3); **REST JSON encoding of choice-elements still unconfirmed.**
4. Exact JSON field name for a security-profile attachment on a Security Rule — XML/config-tree shape now confirmed as `profile-setting.group`/`profile-setting.profiles.*` (section 4); **REST JSON byte-shape still unconfirmed.**
5. Exact filter/category value to isolate DNS-related Threat log entries — **now confirmed as `category-of-threatid` (not `subtype`)**; full non-exhaustive category value list still not fully enumerated anywhere.
6. Whether `target=<serial>` works with `type=log` requests — now has strong convergent evidence it does **not** (SDK source + Cortex XSOAR doc); still needs a live test to fully close.
7. Whether log forwarding is configured from managed firewalls to Panorama — product/config question, not an API question. **Check the environment directly.**
8. *(new)* Exact REST JSON encoding of self-closing XML "choice" elements (e.g. `<action><sinkhole/></action>`) for both the Anti-Spyware profile and rule profile-attachments.
9. *(new)* Whether `Policies/SecurityPostRules` is the correct current resource name — only community-forum-confirmed, not found in any official page.
10. *(new)* Whether a completed log job with zero matching entries omits `<logs>` entirely or emits `<logs count="0">` — affects whether `_parse_log_entries`'s empty-list fallback is actually safe.
11. *(new)* Whether PAN-OS ever returns HTTP 429 under real load, and whether the target fleet's management certs are self-signed or enterprise-CA-issued (affects whether the TLS fix in section 9 is urgent).
12. *(new)* Whether the "Superuser (read-only)" dynamic role enforces the same platform-level XML-API-read-only guarantee on Panorama as it does on a standalone firewall (doc wording differs between the two pages).
