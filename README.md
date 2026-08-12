# PaloAlto — PAN-OS / Panorama Drata Custom Connection

Pulls compliance evidence off Palo Alto firewalls + Panorama. Normalizes it. Pushes it to a Drata Custom Connection. Collector → normalizer → publisher, three files, no magic.

No live PAN-OS box was available while building this. Every field shape confirmed vs. guessed lives in [`pan_api_research.md`](pan_api_research.md). Offline test suite in `tests/` built from real captured examples in that doc — run it before touching a real firewall. See caveats at bottom.

Built by Drata SA Team. No other credit needed.

---

## What it collects

| Key | What | API |
|---|---|---|
| `license` | License status (URL Filtering, DNS Security) | XML, `type=op` |
| `url_filtering_profile` | URL Filtering profiles | REST, Objects |
| `dns_security_profile` | DNS Security (lives inside Anti-Spyware profile) | REST, Objects |
| `security_rule` / `security_pre_rule` / `security_post_rule` | Security policy rules, local + Panorama pre/post | REST, Policies |
| `traffic_log_summary` / `url_filtering_log_summary` / `dns_threat_log_summary` | Aggregated log activity, one summary record per device per run | XML, `type=log` |

Full field detail: [`pan_drata_schemas.py`](pan_drata_schemas.py) docstring. Confidence tiers on every claim: [`pan_api_research.md`](pan_api_research.md).

---

## Service account — API permissions to grant

Dedicated, least-privilege, non-shared account. Two tabs on the Admin Role Profile.

**XML API tab — Enable:**
- Op
- Log

Leave rest disabled (Commit, Config, Export, Import, IoT, Report, User-ID).

**REST API tab — Read Only:**
- `Objects.UrlFilteringSecurityProfiles`
- `Objects.AntiSpywareSecurityProfiles`
- `Policies.SecurityRules`
- `Policies.SecurityPreRules`
- `Policies.SecurityPostRules`

Everything else disabled. Details/tradeoffs in `pan_api_research.md` section 7.

---

## Setup — common to both deploy paths below

1. Get code, get deps.

```bash
git clone https://github.com/drata-rv/PaloAlto.git
cd PaloAlto
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

2. Copy config templates, fill real values.

```bash
cp .env.example .env
cp devices.example.json devices.json
```

`devices.json` — real hostnames, serials, device groups. Never commit this file (`.gitignore` already blocks it).

`.env` — fill these:

```
PAN_USERNAME=          # service account from above
PAN_PASSWORD=
DRATA_API_KEY=         # skip if only running --collect-only
DRATA_CONNECTION_ID=
DRATA_RESOURCE_ID=
```

3. Run tests first. No live device needed, offline fixtures only.

```bash
python -m unittest discover -s tests -t .
```

All green before you point this at a real firewall. Non-negotiable.

4. Dry run against real device before trusting output. `--collect-only` skips Drata publish, writes local JSON only.

```bash
source .env  # or export vars some other way
python3 main.py --devices-config devices.json --collect-only --output pan_payload.json
```

Check `pan_payload.json`. `raw` = every device's raw API response. `normalized` = what would've gone to Drata. Inspect both before flipping the switch.

5. Real run, publishes to Drata.

```bash
python3 main.py --devices-config devices.json
```

---

## Deploy option A — local Python (server, VM, laptop, whatever)

Simplest. Machine needs network reachability to every firewall/Panorama in `devices.json`.

Schedule it. Cron, easiest:

```bash
crontab -e
```

```cron
# every 6 hours
0 */6 * * * cd /path/to/PaloAlto && venv/bin/python3 main.py --devices-config devices.json >> /var/log/pan-connector.log 2>&1
```

Or systemd timer if you want proper logging/retry semantics — write a `.service` + `.timer` unit, `ExecStart=` points at the same command.

Log file grows forever if you don't rotate it. Add `logrotate` config, or redirect through your own logging pipe. Your call.

---

## Deploy option B — hosted on Azure

Good fit when Azure already has network/VPN reachability into wherever the firewalls live and you don't want a box to patch. No code changes needed either way — `main.py` is a plain script, both options below just run it on a schedule.

### B1 — Azure Automation Runbook (recommended, no VM)

1. Create an Automation Account (if none exists yet).
2. Import as a **Python 3 runbook**. Upload `main.py` + the other `.py` files as a package, or zip the whole repo and import as a module.
3. Store `PAN_USERNAME` / `PAN_PASSWORD` / `DRATA_API_KEY` / `DRATA_CONNECTION_ID` / `DRATA_RESOURCE_ID` as **Automation Account variables or Key Vault references** — not plaintext in the runbook.
4. Store `devices.json` in an attached Automation Account asset, or pull it from Key Vault / Blob Storage at runtime — don't bake it into the runbook source.
5. Add a **schedule** (Automation Account → Schedules), link it to the runbook. Set your interval.
6. First few runs: trigger manually, check the job output tab for errors before trusting the schedule.

Zero servers to patch. Logs land in the Automation job history automatically.

### B2 — Azure Container Instance / small VM + cron

If you'd rather run this in a container:

1. Build a minimal image — base Python image, `pip install -r requirements.txt`, copy repo in.
2. Push to Azure Container Registry.
3. Run as an **Azure Container Instance** on a restart policy, with the container's entrypoint being a cron daemon (or a sleep-loop wrapper) that calls `python3 main.py --devices-config devices.json` on schedule.
4. Env vars (`PAN_USERNAME` etc.) go in via ACI's secure environment variables, not baked into the image.
5. `devices.json` mounted in via an Azure File Share, not baked into the image either.

More moving parts than the runbook option. Pick this only if you already run other workloads this way and want consistency.

### Not included: Azure Functions

Would need a thin timer-triggered handler wrapping `main()` — not shipped here. `main.py` is deliberately host-agnostic; nothing about it prevents wrapping it in a Function later if that's the preferred pattern. Just isn't done yet. Watch log-polling wait times (`pan_base.py`, up to 120s per log job) against whatever execution timeout your plan gives you if you go this route.

---

## Testing

```bash
python -m unittest discover -s tests -t .
```

43 tests, stdlib `unittest`, zero extra dependencies. Fixtures in `tests/fixtures/` — see that folder's `README.md` for which ones are verbatim-captured from a real device vs. best-effort constructions from confirmed field names.

---

## Known gaps — read before first live run

- `get_dns_threat_logs()` uses a best-effort OR'd query across every `category-of-threatid` example value found in research — full category enumeration is an open gap. Revisit once confirmed live.
- REST JSON byte-shape of `profile-setting` and DNS Security category choice-elements is a best-effort construction, not a confirmed wire example. Check against your device's own `/restapi-doc` on first run.
- Whether `Policies/SecurityPostRules` is the exact current resource name is only community-forum-confirmed, not official-docs-confirmed.
- No concurrency anywhere in collection — deliberate. Sequential by design. Palo Alto's own guidance caps concurrent calls around 5/device if you ever do add it.

Full list, with citations: `pan_api_research.md`, "Items That Must Be Confirmed" section.

---

Drata SA Team
