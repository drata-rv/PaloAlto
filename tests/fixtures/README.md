# Fixtures

If you don't have a live PAN-OS device to test against yet, these fixtures
are the only validation this connector gets before it touches a real
firewall. Each file below is marked either **captured** (transcribed
verbatim from a real device response quoted in `pan_api_research.md`) or
**constructed** (built from confirmed field names/shapes in that doc, but the
exact byte-for-byte encoding was not itself found in an official example —
same "open gap" `pan_api_research.md` already flags for these resources).

| File | Status | Source |
|---|---|---|
| `license_response_vm50.xml` | captured (first entry) + constructed (second entry) | `pan_api_research.md` section 2 — real VM-50 response via `pan-python`'s `doc/panlicapi.rst`. Second entry added to exercise the `expired=yes` / `authcode`-present branches the real example doesn't cover. |
| `log_job_submit_response.xml` | captured | `pan_api_research.md` section 5 |
| `log_job_poll_inprogress.xml` | constructed | The doc confirms the poll-completion xpath as `./result/job/status` (i.e. `<status>` nested inside `<job>`, not a sibling) but doesn't quote a full poll-response example — `<job><id>/<status>` nesting and the `ACT` status code follow standard PAN-OS job-status convention (same shape used by `show jobs id`/commit-status polling). |
| `log_job_poll_finished_with_results.xml` | captured (the `./result/log/logs/entry` shape + `type`/`subtype`) + constructed (job/status nesting + filler fields) | section 5 — the doc's quoted `<log>` example is truncated (`...`); the `<job><status>` block isn't in the quoted excerpt at all (see above), so it's built to match the confirmed xpath. |
| `log_job_poll_finished_zero_results.xml` | constructed — **the critical regression fixture** | `status=FIN` nested under `<job>` with no `<log>` node at all — exercises the exact bug described in section 5 (a zero-result job finishing without ever populating `<log>`). |
| `url_filtering_profile_response.json` | constructed | Field names from section 3; REST JSON byte-shape of choice-elements is an explicitly open gap in the doc — this is a plausible construction, not a confirmed wire example. |
| `dns_security_profile_response.json` | constructed | Field names/nesting from section 3 (Iron Skillet source) — `log-level` (not `log-severity`), 9 category names, `sinkhole` block. Same open-gap caveat as above. |
| `security_rules_response.json` | constructed | `profile-setting.group` and `profile-setting.profiles.*` shapes from section 4 (XML/config-tree shape confirmed via two SDKs; REST JSON byte-shape is an open gap). Includes one `disabled=yes` rule and one implicitly-enabled rule. |
| `security_pre_rules_response.json` / `security_post_rules_response.json` | constructed | Same shape, device-group scoped. |
