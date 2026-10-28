"""
PAN-OS / Panorama compliance evidence connector for Drata Custom Connections.

    auth.py       API key generation (keygen) per host
    base.py       shared HTTP: XML API, REST API, async log jobs, retries
    firewall.py   the evidence calls (license, profiles, rules, logs)
    schemas.py    normalizers: raw PAN-OS responses -> Drata records
    publisher.py  batched upsert to a Drata Custom Connection
    runner.py     collect -> normalize -> publish orchestration and CLI

Entry point: pan_main.py at the repository root.

Drata Solutions Architect team
"""
