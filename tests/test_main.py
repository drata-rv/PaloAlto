import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import requests

from tests._helpers import load_fixture

from pan_connector import runner as m


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
        self.assertEqual(len(contexts), 5)  # 3 firewalls + 1 device group + the synthetic Shared context

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

        shared = by_id["panorama-shared"]
        self.assertEqual(shared.scope, "DEVICE_GROUP")
        self.assertIsNone(shared.device_group)
        self.assertIs(shared.connector, device_group.connector)


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


def _ctx(**overrides):
    defaults = dict(id="d", hostname="h", scope="FIREWALL", managed_by="DIRECT", site="S", vsys="vsys1")
    defaults.update(overrides)
    return m.DeviceContext(**defaults)


class TestLocationSets(unittest.TestCase):
    def test_direct_firewall_objects_are_vsys_plus_shared(self):
        calls = m._object_location_kwargs(_ctx())
        self.assertEqual([c["location"] for c in calls], ["vsys", "shared"])

    def test_panorama_managed_firewall_also_gets_panorama_pushed(self):
        # Objects/rules pushed from Panorama are NOT returned under location=vsys.
        objects = m._object_location_kwargs(_ctx(managed_by="PANORAMA"))
        rules = m._policy_location_kwargs(_ctx(managed_by="PANORAMA"))
        self.assertIn({"location": "panorama-pushed", "vsys": "vsys1"}, objects)
        self.assertEqual([c["location"] for c in rules], ["vsys", "panorama-pushed"])

    def test_direct_firewall_rules_do_not_request_panorama_pushed(self):
        rules = m._policy_location_kwargs(_ctx())
        self.assertEqual([c["location"] for c in rules], ["vsys"])

    def test_panorama_device_group_and_shared(self):
        dg = _ctx(scope="DEVICE_GROUP", managed_by="PANORAMA", device_group="azure-dg")
        shared = _ctx(scope="DEVICE_GROUP", managed_by="PANORAMA", device_group=None)
        self.assertEqual(m._object_location_kwargs(dg), [{"location": "device-group", "device_group": "azure-dg"}])
        self.assertEqual(m._object_location_kwargs(shared), [{"location": "shared"}])
        self.assertEqual(m._pre_post_rule_kwargs(dg), {"device_group": "azure-dg"})
        self.assertEqual(m._pre_post_rule_kwargs(shared), {"location": "shared"})


class TestCollectMultipleLocations(unittest.TestCase):
    def _resource(self, calls):
        return m._Resource(
            key="obj", method_name="obj", normalizer=lambda *a, **k: {}, evidence_type="OBJ",
            label="obj", scopes=frozenset({"FIREWALL"}), call_kwargs=lambda d: calls,
        )

    def test_results_from_every_location_are_combined(self):
        connector = Mock(obj=Mock(side_effect=lambda **kw: [{"@name": kw["location"]}]))
        device = _ctx(connector=connector)
        resource = self._resource([{"location": "vsys"}, {"location": "shared"}])
        with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
            raw = m._collect([device], [resource], tmp.name, "2026-08-12T00:00:00Z")
        self.assertEqual([e["@name"] for e in raw["d"]["obj"]], ["vsys", "shared"])

    def test_one_failing_location_keeps_the_others(self):
        def obj(**kw):
            if kw["location"] == "shared":
                raise RuntimeError("bad location")
            return [{"@name": kw["location"]}]

        device = _ctx(connector=Mock(obj=Mock(side_effect=obj)))
        resource = self._resource([{"location": "vsys"}, {"location": "shared"}])
        with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
            raw = m._collect([device], [resource], tmp.name, "2026-08-12T00:00:00Z")
        self.assertEqual(raw["d"]["obj"], [{"@name": "vsys"}])

    def test_resource_errors_only_if_every_location_fails(self):
        device = _ctx(connector=Mock(obj=Mock(side_effect=RuntimeError("down"))))
        resource = self._resource([{"location": "vsys"}, {"location": "shared"}])
        with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
            raw = m._collect([device], [resource], tmp.name, "2026-08-12T00:00:00Z")
        self.assertIn("error", raw["d"]["obj"])


class TestUnreachableHostSkipping(unittest.TestCase):
    TS = "2026-08-12T00:00:00Z"

    def _resources(self, n):
        return [
            m._Resource(
                key=f"r{i}", method_name="call", normalizer=lambda *a, **k: {}, evidence_type=f"R{i}",
                label=f"r{i}", scopes=frozenset({"FIREWALL"}),
            )
            for i in range(n)
        ]

    def _run(self, devices, resources):
        with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
            return m._collect(devices, resources, tmp.name, self.TS)

    def test_skips_remaining_calls_after_three_connect_timeouts(self):
        call = Mock(side_effect=requests.exceptions.ConnectTimeout("timed out"))
        raw = self._run([_ctx(connector=Mock(host="10.0.0.1", call=call))], self._resources(7))

        self.assertEqual(call.call_count, 3)
        for i in range(3):
            self.assertNotIn("skipped", raw["d"][f"r{i}"]["error"])
        for i in range(3, 7):
            self.assertTrue(raw["d"][f"r{i}"]["error"].startswith("skipped: 10.0.0.1 unreachable"))

    def test_a_success_resets_the_count(self):
        timeout = requests.exceptions.ConnectTimeout("timed out")
        call = Mock(side_effect=[timeout, timeout, [{"@name": "ok"}], timeout, timeout])
        raw = self._run([_ctx(connector=Mock(host="10.0.0.1", call=call))], self._resources(5))

        self.assertEqual(call.call_count, 5)
        self.assertEqual(raw["d"]["r2"], [{"@name": "ok"}])

    def test_other_errors_never_trigger_skipping(self):
        call = Mock(side_effect=RuntimeError("HTTP 403"))
        self._run([_ctx(connector=Mock(host="10.0.0.1", call=call))], self._resources(10))
        self.assertEqual(call.call_count, 10)

    def test_read_timeout_does_not_count_as_unreachable(self):
        call = Mock(side_effect=requests.exceptions.ReadTimeout("slow"))
        self._run([_ctx(connector=Mock(host="10.0.0.1", call=call))], self._resources(6))
        self.assertEqual(call.call_count, 6)

    def test_host_is_shared_across_contexts(self):
        # e.g. every device group of one Panorama uses the same connector
        call = Mock(side_effect=requests.exceptions.ConnectTimeout("timed out"))
        connector = Mock(host="panorama.internal", call=call)
        devices = [_ctx(id="dg1", connector=connector), _ctx(id="dg2", connector=connector)]
        raw = self._run(devices, self._resources(2))

        self.assertEqual(call.call_count, 3)
        self.assertTrue(raw["dg2"]["r1"]["error"].startswith("skipped: panorama.internal unreachable"))

    def test_other_hosts_are_unaffected(self):
        dead = Mock(host="10.0.0.1", call=Mock(side_effect=requests.exceptions.ConnectTimeout("timed out")))
        alive = Mock(host="10.0.0.2", call=Mock(return_value=[{"@name": "ok"}]))
        raw = self._run([_ctx(id="dead", connector=dead), _ctx(id="alive", connector=alive)], self._resources(4))

        self.assertEqual(alive.call.call_count, 4)
        self.assertEqual(raw["alive"]["r3"], [{"@name": "ok"}])

    def test_remaining_locations_of_one_resource_are_skipped_too(self):
        call = Mock(side_effect=requests.exceptions.ConnectTimeout("timed out"))
        resource = m._Resource(
            key="obj", method_name="call", normalizer=lambda *a, **k: {}, evidence_type="OBJ",
            label="obj", scopes=frozenset({"FIREWALL"}),
            call_kwargs=lambda d: [{"location": str(i)} for i in range(6)],
        )
        raw = self._run([_ctx(connector=Mock(host="10.0.0.1", call=call))], [resource])

        self.assertEqual(call.call_count, 3)
        self.assertIn("skipped: 10.0.0.1 unreachable", raw["d"]["obj"]["error"])


class TestLoudFailure(unittest.TestCase):
    def test_failures_list_dead_devices_and_failed_resources_only(self):
        raw = {
            "dead": {"error": "boom"},
            "partial": {
                "license": [{"feature": "x"}],
                "security_rule": {"error": "HTTP 403"},
            },
            "no-host": {"security_rule": {"error": f"{m._NOT_COLLECTED} no direct host configured for this device"}},
            "healthy": {"license": [{"feature": "x"}]},
        }
        self.assertEqual(m._collection_failures(raw), ["dead", "partial/security_rule"])

    def _run_main(self, raw, records):
        env = {"PAN_USERNAME": "u", "PAN_PASSWORD": "p"}
        with patch.dict(os.environ, env), \
                patch("sys.argv", ["pan_main.py", "--devices-config", "x.json"]), \
                patch.object(m, "_load_devices_config", return_value={}), \
                patch.object(m, "_validate_config"), \
                patch.object(m, "_build_device_contexts", return_value=[]), \
                patch.object(m, "_collect", return_value=raw), \
                patch.object(m, "_normalize", return_value=records), \
                patch.object(m, "_write_snapshot"), \
                patch.object(m, "_publish") as publish:
            try:
                m.main()
            finally:
                self.publish = publish

    def test_no_records_raises(self):
        with self.assertRaises(m.CollectionError) as ctx:
            self._run_main({"dead": {"error": "timed out"}}, [])
        self.assertIn("no records collected", str(ctx.exception))
        self.assertIn("dead", str(ctx.exception))

    def test_partial_failure_publishes_first_then_raises(self):
        raw = {"ok": {"license": [{}]}, "bad": {"error": "timed out"}}
        with self.assertRaises(m.CollectionError) as ctx:
            self._run_main(raw, [{"id": "a"}])
        self.publish.assert_called_once_with([{"id": "a"}])
        self.assertIn("1 records published", str(ctx.exception))
        self.assertIn("bad", str(ctx.exception))

    def test_clean_run_does_not_raise(self):
        self._run_main({"ok": {"license": [{}]}}, [{"id": "a"}])
        self.publish.assert_called_once_with([{"id": "a"}])


class TestRunSurvivesBadInputs(unittest.TestCase):
    def test_one_unnormalizable_record_is_skipped_not_fatal(self):
        def normalizer(entry, device, ts, **kw):
            if entry["@name"] == "bad":
                raise KeyError("unexpected shape")
            return {"id": entry["@name"]}

        resource = m._Resource(
            key="k", method_name="k", normalizer=normalizer, evidence_type="K",
            label="k", scopes=frozenset({"FIREWALL"}),
        )
        raw = {"d": {"k": [{"@name": "a"}, {"@name": "bad"}, {"@name": "c"}]}}
        records = m._normalize(raw, [_ctx()], [resource], "2026-08-12T00:00:00Z")
        self.assertEqual([r["id"] for r in records], ["a", "c"])

    def test_unwritable_output_path_does_not_abort(self):
        # e.g. an Azure Function running from a read-only package
        m._write_snapshot("/nonexistent-dir/definitely/not/writable.json", "ts", {}, [])  # must not raise


if __name__ == "__main__":
    unittest.main()
