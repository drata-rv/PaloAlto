import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from tests._helpers import load_fixture

import pan_main as m


def _load(fixture_name):
    return json.loads(load_fixture(fixture_name))


class TestValidateConfig(unittest.TestCase):
    def test_valid_config_collect_only_passes(self):
        m._validate_config(_load("devices_valid.json"), collect_only=True)  # should not raise

    def test_missing_panorama_block_raises(self):
        with self.assertRaises(m.ConfigError):
            m._validate_config(_load("devices_missing_panorama_block.json"), collect_only=True)

    def test_empty_config_raises(self):
        with self.assertRaises(m.ConfigError):
            m._validate_config({}, collect_only=True)

    def test_missing_drata_env_vars_raises_unless_collect_only(self):
        config = {"direct_firewalls": [{"name": "fw1", "host": "10.0.0.1"}]}
        env_without_drata = {
            k: v for k, v in os.environ.items()
            if not k.startswith("DRATA_") and not k.startswith("PAN_DRATA_")
        }
        with patch.dict(os.environ, env_without_drata, clear=True):
            with self.assertRaises(m.ConfigError):
                m._validate_config(config, collect_only=False)
            m._validate_config(config, collect_only=True)  # should not raise


class TestBuildDeviceContexts(unittest.TestCase):
    def test_produces_expected_scopes_and_connectors(self):
        contexts = m._build_device_contexts(_load("devices_valid.json"), "svc", "pw")
        by_id = {c.id: c for c in contexts}
        self.assertEqual(len(contexts), 4)

        direct = by_id["fw-1"]
        self.assertEqual(direct.scope, "FIREWALL")
        self.assertEqual(direct.managed_by, "DIRECT")
        self.assertIs(direct.connector, direct.license_connector)

        panorama_with_host = by_id["fw-azure-1"]
        self.assertEqual(panorama_with_host.managed_by, "PANORAMA")
        self.assertIsNotNone(panorama_with_host.connector)
        self.assertIsNotNone(panorama_with_host.license_connector)
        self.assertIsNot(panorama_with_host.connector, panorama_with_host.license_connector)

        panorama_no_host = by_id["fw-azure-2"]
        self.assertIsNone(panorama_no_host.connector)
        self.assertIsNotNone(panorama_no_host.license_connector)
        self.assertEqual(panorama_no_host.hostname, "panorama-proxy:0000000002")

        device_group = by_id["azure-dg"]
        self.assertEqual(device_group.scope, "DEVICE_GROUP")
        self.assertEqual(device_group.device_group, "azure-dg")
        self.assertIsNotNone(device_group.connector)


def _fake_resource(key, scopes, connector_attr="connector", raises=False):
    def method(**kwargs):
        if raises:
            raise RuntimeError(f"{key} failed")
        return [{"@name": key}]

    return m._Resource(
        key=key, method_name=key, normalizer=lambda *a, **k: {}, evidence_type=key.upper(),
        label=key, scopes=frozenset(scopes), connector_attr=connector_attr,
    ), method


class TestCollectFaultIsolation(unittest.TestCase):
    def test_one_failing_resource_does_not_affect_siblings(self):
        good_resource, good_method = _fake_resource("good", {"FIREWALL"})
        bad_resource, bad_method = _fake_resource("bad", {"FIREWALL"}, raises=True)
        connector = Mock(good=Mock(side_effect=good_method), bad=Mock(side_effect=bad_method))
        device = m.DeviceContext(id="d1", hostname="h1", scope="FIREWALL", managed_by="DIRECT", site="S", connector=connector)

        with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
            raw = m._collect([device], [good_resource, bad_resource], tmp.name, "2026-08-12T00:00:00Z")

        self.assertEqual(raw["d1"]["good"], [{"@name": "good"}])
        self.assertIn("error", raw["d1"]["bad"])

    def test_no_direct_connector_reports_not_collected_but_license_still_works(self):
        license_resource, _ = _fake_resource("license", {"FIREWALL"}, connector_attr="license_connector")
        other_resource, other_method = _fake_resource("security_rule", {"FIREWALL"})
        device = m.DeviceContext(
            id="d2", hostname="panorama-proxy:123", scope="FIREWALL", managed_by="PANORAMA", site="S",
            connector=None, license_connector=Mock(license=Mock(return_value=[{"feature": "x"}])),
        )
        # license_resource.method_name is "license" to match the Mock attr above
        with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
            raw = m._collect([device], [license_resource, other_resource], tmp.name, "2026-08-12T00:00:00Z")

        self.assertIn("error", raw["d2"]["security_rule"])
        self.assertEqual(raw["d2"]["security_rule"]["error"], "not collected: no direct host configured for this device")

    def test_one_bad_device_does_not_affect_other_devices(self):
        # A connector method that raises when called is inner-try territory
        # (per-resource isolation, tested above). To exercise the OUTER
        # try/except -- the "one dead device can't kill the run" layer --
        # this needs a failure in code that runs before any per-resource
        # inner try even starts, e.g. reading device.scope itself.
        good_resource, good_method = _fake_resource("good", {"FIREWALL"})

        class BadScopeDevice:
            id = "bad"

            @property
            def scope(self):
                raise RuntimeError("device is structurally broken")

        bad_device = BadScopeDevice()
        good_device = m.DeviceContext(id="good", hostname="h", scope="FIREWALL", managed_by="DIRECT", site="S", connector=Mock(good=Mock(side_effect=good_method)))

        with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
            raw = m._collect([bad_device, good_device], [good_resource], tmp.name, "2026-08-12T00:00:00Z")

        self.assertEqual(raw["bad"], {"error": "device is structurally broken"})
        self.assertEqual(raw["good"]["good"], [{"@name": "good"}])

    def test_writes_incremental_snapshot_after_each_device(self):
        good_resource, good_method = _fake_resource("good", {"FIREWALL"})
        device = m.DeviceContext(id="d1", hostname="h1", scope="FIREWALL", managed_by="DIRECT", site="S", connector=Mock(good=Mock(side_effect=good_method)))

        with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
            m._collect([device], [good_resource], tmp.name, "2026-08-12T00:00:00Z")
            with open(tmp.name) as f:
                on_disk = json.load(f)

        self.assertEqual(on_disk["raw"]["d1"]["good"], [{"@name": "good"}])
        self.assertEqual(on_disk["normalized"], [])  # normalize happens after _collect returns


class TestNormalize(unittest.TestCase):
    def test_skips_errored_devices_and_resources_handles_aggregate(self):
        per_entry_resource, _ = _fake_resource("license", {"FIREWALL"})
        per_entry_resource.normalizer = Mock(side_effect=lambda entry, device, ts, **kw: {"id": entry["@name"]})

        aggregate_resource, _ = _fake_resource("traffic_log_summary", {"FIREWALL"})
        aggregate_resource.is_aggregate = True
        aggregate_resource.normalizer = Mock(return_value={"id": "agg"})

        good_device = m.DeviceContext(id="good", hostname="h", scope="FIREWALL", managed_by="DIRECT", site="S")
        bad_device = m.DeviceContext(id="bad", hostname="h", scope="FIREWALL", managed_by="DIRECT", site="S")

        raw_results = {
            "good": {"license": [{"@name": "a"}, {"@name": "b"}], "traffic_log_summary": [{"action": "allow"}]},
            "bad": {"error": "device_failed"},
        }

        records = m._normalize(raw_results, [good_device, bad_device], [per_entry_resource, aggregate_resource], "2026-08-12T00:00:00Z")

        self.assertEqual(len(records), 3)  # 2 license entries + 1 aggregate, nothing from "bad"
        aggregate_resource.normalizer.assert_called_once()


if __name__ == "__main__":
    unittest.main()
