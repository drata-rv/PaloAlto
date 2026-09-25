# Handoff Notes — PAN Connection

Rewritten 2026-08-12 after bringing the connector from collection-only prototype to a
full connector → normalizer → publisher pipeline (see README.md). This file is the
pickup point for whoever continues.

## What exists now

- `pan_main.py` (renamed from `main.py`), `pan_auth.py`, `pan_base.py`, `pan_firewall.py`
  — collector, with all research-confirmed bug fixes applied (log-poll `status==FIN`
  check, license `authcode`/`expired` typing, TLS `bool|str`, one-shot re-auth on stale
  key, `get_dns_threat_logs` wired into collection, config validation, per-device fault
  isolation, incremental output writes).
- `pan_drata_schemas.py` / `pan_drata_publisher.py` — new normalizer + publisher layer,
  mirroring the sibling Microsoft connector's pattern. Publishes to a single
  `PAN_DRATA_RESOURCE_ID`.
- `tests/` — offline unittest suite (50 tests) built from real captured examples in
  `pan_api_research.md`, since there's still no live device to test against. Run with
  `pip install -r requirements-dev.txt && python -m unittest discover -s tests -t .`.
- `README.md`, `.env.example`, `requirements.txt` — previously missing, now present.
- `pan_api_research.md` — unchanged since the last research pass; still the source of
  truth for every confirmed-vs-guessed field shape.
- `schema.json` (added 2026-09-25) — the actual Custom Connection resource schema. This
  was a real gap until now: `pan_drata_publisher.py` was built to POST to an *existing*
  `PAN_DRATA_CONNECTION_ID`/`PAN_DRATA_RESOURCE_ID`, but nothing defined the schema you'd
  submit to Drata to create that connection + resource in the first place, so those env
  vars had no real values to be filled in with. `schema.json` covers the full field union
  across all 7 evidence types (one resource holds all of them, distinguished by
  `evidenceType`), validated against every real normalizer output in `tests/test_schema.py`
  (`requirements-dev.txt` adds `jsonschema`, test-only). README's "Custom Connection
  schema" section has the exact steps to submit it in Drata. **Still needs a human to
  actually do that submission** — this only produces the artifact, it doesn't create the
  connection or mint the real `PAN_DRATA_CONNECTION_ID`/`PAN_DRATA_RESOURCE_ID` values.

## Deployment decision (resolved 2026-08-14)

**Hosting is decided: this connector deploys into the same Azure Function App as the
Microsoft connector** (`scu-pcs-drata-fn01` per the portal screenshot — Cameron's call).
That app has no version-controlled deployment wrapper anywhere: `host.json` and whatever
declares the existing `daily_run` timer trigger live only inside the Function App itself
(not in `suncoastmicrosoftcustomconnectionprototype-Suncoast`'s git history — confirmed by
fetching origin directly, zero drift). Cameron's actual workflow is: download the
Microsoft repo's source as a zip from GitHub, extract, upload into the Function App
(overlaying, not clean-syncing — that's *why* the untracked wrapper survives every
update), add environment variables, done.

**Consequence for adding PAN as a second function in that same app/zip — already applied
to this repo:**
- `main.py` → renamed to **`pan_main.py`** (matching the existing `pan_`-prefix
  convention already used for `pan_auth.py`/`pan_base.py`/`pan_firewall.py`). The
  Microsoft repo's `main.py` is a generic, unprefixed name — two files named `main.py`
  can't coexist in the same flat deployment package.
- `DRATA_CONNECTION_ID` / `DRATA_RESOURCE_ID` → renamed to **`PAN_DRATA_CONNECTION_ID`**
  / **`PAN_DRATA_RESOURCE_ID`** everywhere (`pan_main.py`, `pan_drata_publisher.py`,
  `.env.example`, `README.md`). Azure Function App settings are shared app-wide across
  every function in the app; the Microsoft connector already owns the unprefixed names
  for its own (different) Custom Connection, so identical names would silently collide
  once both land in the same App Settings blade.
- `DRATA_API_KEY` left **unprefixed/shared** — assumed to be one account-level Drata API
  key valid for both connections, not connection-specific. **Not yet confirmed with
  Suncoast/Cameron — if Drata API keys turn out to be provisioned per Custom Connection,
  this needs the same `PAN_` prefix treatment before deploy.**
- Not yet done, still needed before this actually drops into Cameron's zip: someone needs
  to pull the real deployment wrapper (Azure Portal → the Function App → **Download app
  content**) to see how `daily_run` is actually declared (`function_app.py` v2 model vs.
  per-function `function.json` v1 folder), then add a second trigger for PAN's
  `pan_main.py` inside that same wrapper. That file isn't in either git repo — grab it
  directly from Azure before trying to merge the two codebases into one zip.
- Both connectors' `requirements.txt` are already trivially compatible (`requests>=2.28.0`
  in both, nothing else) — no dependency conflict to resolve when merged.

## Non-code items still genuinely open (from `pan_custom_connection_spec.md` in the
sibling Microsoft repo — resurface these; none are blocked on more code work)

1. **Automation hosting** — resolved above (same Function App as Microsoft). Revisit
   execution-time limits regardless: a
   full run across the fleet involves multiple async log-polling loops that can each
   take up to 120s (`max_wait_seconds` in `pan_base.py`), and a Function's timeout
   could truncate a run mid-fleet. The incremental-write design already in `_collect`
   softens this (partial evidence isn't lost) but doesn't eliminate the risk.
2. **Full-fleet vs. representative-sample evidence policy** — unresolved; auditor
   requirement unknown (historically only one box's evidence was ever provided
   manually). Current design collects every device listed in `devices.json` every
   run. Whichever way this resolves is a small `--devices-filter`/`site`-tag addition,
   not a redesign.
3. **Dedicated least-privilege service account** — ticket status unknown as of last
   research pass. Recommended XML/REST scoping is in `pan_api_research.md` section 7.
   This is a hard blocker for pointing the connector at any real device, not just a
   nice-to-have.
4. **Change control filing** — status unknown.
5. **DCF-to-CIS/NIST control mapping** for the 34 Drata Control Framework codes tied to
   this connection — not yet done via Drata's control library. This determines the
   actual pass/fail test logic (mirroring the Microsoft side's `tests.md`/
   `drata_test_blocks.md`) that should eventually be authored against this schema —
   in particular, confirm before that logic is written:
   - Is `AT_RISK`-style "license expiring soon" needed, or is COMPLIANT/NONCOMPLIANT
     (off the `expired` bool) sufficient?
   - Is "always CONFIGURED, `affectedCount` carries the signal" the right semantics
     for the three log summaries, or should zero-denies map to a different status?
6. **TLS CA bundle** — `verify_tls` now accepts a file path (not just bool), but
   someone needs to hand over Suncoast's actual internal CA bundle path. Ships with a
   safe default (`true`) until then.

## Remaining open research gaps (unchanged from `pan_api_research.md`'s own checklist
— still need a live device or Suncoast's direct answer, don't re-research these)

- Exact REST JSON byte-shape of `profile-setting` and self-closing XML "choice"
  elements (e.g. `<action><sinkhole/></action>`) — `pan_drata_schemas.py`'s handling
  of these is a best-effort construction from confirmed XML/config-tree shapes.
- Whether `Policies/SecurityPostRules` is the correct current resource name — only
  community-forum-confirmed.
- Whether a completed log job with zero matching entries omits `<logs>` entirely or
  emits `<logs count="0">` (both are handled, but only one has been exercised against
  anything resembling a real response).
- Whether PAN-OS ever returns HTTP 429 under real load.
- Whether Suncoast's management certs are self-signed or enterprise-CA-issued.
- Whether "Superuser (read-only)" enforces the same platform-level guarantee on
  Panorama as it does on a standalone firewall.

## Constraints to keep in mind

- **No test device, no Palo Alto support** — still true. Don't propose "just test it
  against a live box" as a next step; it's not available. The `tests/` fixture suite
  is the working validation method until that changes.
- **Cap agent fan-out at 4 per task** — user-set limit (tightened from an earlier cap
  of 5 after a prior over-large research run).
- **No concurrency in `_collect`** — deliberate, not an oversight. Revisit only if a
  hosting decision (item 1 above) actually requires faster wall-clock time, and cap
  at PANW's own confirmed ~5-concurrent-calls-per-device guidance if so.
