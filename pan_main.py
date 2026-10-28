"""
pan_main.py
Entry point. Kept at the repository root so the Azure Function wrapper (which
imports `pan_main`) and the CLI keep working; the implementation lives in
pan_connector/runner.py.

    python3 pan_main.py --devices-config devices.json [--collect-only]

Drata Solutions Architect team
"""

from pan_connector.runner import CollectionError, cli, main  # noqa: F401

if __name__ == "__main__":
    cli()
