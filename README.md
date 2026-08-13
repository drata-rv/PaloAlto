# PaloAlto — PAN-OS / Panorama Drata Custom Connection

Collects compliance evidence from Palo Alto firewalls and Panorama, normalizes it, and publishes it to a Drata Custom Connection.

---

## What it collects

| Key | What | API |
|---|---|---|
| `license` | License status (URL Filtering, DNS Security) | XML, `type=op` |
| `url_filtering_profile` | URL Filtering profiles | REST, Objects |
| `dns_security_profile` | DNS Security (lives inside Anti-Spyware profile) | REST, Objects |
| `security_rule` / `security_pre_rule` / `security_post_rule` | Security policy rules, local + Panorama pre/post | REST, Policies |
| `traffic_log_summary` / `url_filtering_log_summary` / `dns_threat_log_summary` | Aggregated log activity, one summary record per device per run | XML, `type=log` |

Field reference: [`pan_drata_schemas.py`](pan_drata_schemas.py). API reference: [`pan_api_research.md`](pan_api_research.md).

---

## Service account — API permissions to grant

Dedicated, least-privilege, non-shared account. Two tabs on the Admin Role Profile.

**XML API tab — Enable:**
- Op
- Log

Leave everything else disabled (Commit, Config, Export, Import, IoT, Report, User-ID).

**REST API tab — Read Only:**
- `Objects.UrlFilteringSecurityProfiles`
- `Objects.AntiSpywareSecurityProfiles`
- `Policies.SecurityRules`
- `Policies.SecurityPreRules`
- `Policies.SecurityPostRules`

Everything else disabled.

---

## Setup

1. Get code, install deps.

```bash
git clone git@github.com:drata-rv/PaloAlto.git
cd PaloAlto
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

2. Copy config templates, fill in real values.

```bash
cp .env.example .env
cp devices.example.json devices.json
```

`devices.json` — real hostnames, serials, device groups.

`.env`:

```
PAN_USERNAME=
PAN_PASSWORD=
DRATA_API_KEY=
DRATA_CONNECTION_ID=
DRATA_RESOURCE_ID=
```

3. Run the test suite.

```bash
python -m unittest discover -s tests -t .
```

4. Dry run against a real device, no publish.

```bash
source .env
python3 main.py --devices-config devices.json --collect-only --output pan_payload.json
```

`pan_payload.json` contains `raw` (every device's raw API response) and `normalized` (records that would publish to Drata).

5. Full run, publishes to Drata.

```bash
python3 main.py --devices-config devices.json
```

---

## Deploy — local Python

Runs on any server/VM/laptop with network reachability to every firewall/Panorama in `devices.json`.

Cron:

```bash
crontab -e
```

```cron
# every 6 hours
0 */6 * * * cd /path/to/PaloAlto && venv/bin/python3 main.py --devices-config devices.json >> /var/log/pan-connector.log 2>&1
```

Or a systemd `.service` + `.timer` unit, `ExecStart=` pointing at the same command.

---

## Deploy — hosted on Azure

### Option 1 — Azure Automation Runbook

1. Create an Automation Account.
2. Import as a **Python 3 runbook** — upload `main.py` and the other `.py` files as a package, or zip the repo and import as a module.
3. Store `PAN_USERNAME` / `PAN_PASSWORD` / `DRATA_API_KEY` / `DRATA_CONNECTION_ID` / `DRATA_RESOURCE_ID` as Automation Account variables or Key Vault references.
4. Store `devices.json` as an Automation Account asset, or pull it from Key Vault / Blob Storage at runtime.
5. Add a schedule (Automation Account → Schedules), link it to the runbook.
6. Trigger manually first, check the job output tab, then let the schedule take over.

### Option 2 — Azure Container Instance

1. Build a minimal image: base Python image, `pip install -r requirements.txt`, copy repo in.
2. Push to Azure Container Registry.
3. Run as an Azure Container Instance with the entrypoint running a cron daemon (or scheduling wrapper) that calls `python3 main.py --devices-config devices.json`.
4. Set env vars via ACI's secure environment variables.
5. Mount `devices.json` via an Azure File Share.

---

Drata SA Team
