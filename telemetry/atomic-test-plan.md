# Atomic test plan — isolated-VM validation

Status: **prepared, not executed.** Every detection is `fixture-validated`; nothing below has
been run. The per-detection records are filled in from the fixture metadata
(`tests/fixtures/telemetry/DET-00N/meta.yml`), the Sigma rules, and the write-ups, so the only
blank fields are the ones a run produces. When the run happens, the result — including a miss —
is published as measured.

## Why this run is the gate

`fixture-validated` proves the compiled query and the field mapping against hand-authored,
ECS-shaped events. `validated` additionally requires that the Atomic test executes in a disposable
VM, the sensor produces the source event, the ingest pipeline maps it, the compiled query returns
it, and the negative control stays silent. An absent alert only means something if the source
event was actually generated and ingested (`docs/DESIGN.md`, "Lifecycle").

## Environment baseline (record before the first test)

| Item | Plan | Recorded at run time |
| --- | --- | --- |
| Guest | Windows 10/11 evaluation build in VirtualBox on the `D:` drive; **host-only adapter only**, no bridged or NAT adapter while tests run | build, VirtualBox version |
| Snapshots | `clean-base` before any sensor; `sensors-installed` after Sysmon + shipper + audit policy | snapshot IDs (`host_snapshot`) |
| Sysmon | A reviewed configuration that includes ProcessCreate (EventID 1), RegistryEvent SetValue for the Run/RunOnce keys (EventID 13), FileCreate (EventID 11) and ProcessAccess to lsass (EventID 10) | config file SHA-256 (`sensor_config_id`), Sysmon version |
| Audit policy | Logon success (Security 4624) on; optionally Other Object Access Events for 4698 (future-work logsource) | `auditpol /get` output |
| Shipper | Winlogbeat (Sysmon + Security channels) with **file output**; exported files copied to the lab host over the host-only network or a shared folder, then ingested into the lab Elasticsearch through the Elastic Windows/Sysmon ingest pipelines so field names match the compiled queries | shipper version, pipeline IDs |
| Time | Guest clock compared with the host before each test | offset |
| Atomic Red Team | Upstream commit pinned and recorded; only the tests named below; every prerequisite (ProcDump, a lab-served script) staged in the guest before it goes offline; no test may reach the internet | commit SHA |

A field-mapping mismatch between the exported events and the fixtures is a finding for
`docs/validation-log.md`, not something to patch by hand in the exported events.

## Run procedure (per detection)

1. Revert to `sensors-installed`; note the UTC start time.
2. Run the negative control first, then the positive test, from the account and privilege level
   the record names.
3. Wait for the shipper to flush; export the events for the window; note the UTC end time.
4. Run the upstream `cleanup_command`, then revert the snapshot.
5. Ingest the export into the lab Elasticsearch (index `detection-lab-vm-det-00n`) and run the
   compiled query from `detections/compiled/elastic/DET-00N.dsl.json`. Pass = the positive event(s)
   are returned and the negative control is not.
6. Sanitise the exported events (`evidence/README.md`), hash them, add them to `evidence/` with
   `EV-DET-00N-VM-POS` / `EV-DET-00N-VM-NEG` IDs, and a screenshot of the alert if Kibana is up.
7. Fill the record below and the VM columns of `telemetry/validation-matrix.csv`.

## Promotion to `validated` (mechanical)

- `detections/catalog.yml`: `positive_test_id` / `negative_test_id` = the Atomic GUIDs;
  `evidence_ids` = the new `EV-DET-00N-VM-*` rows; `status: validated`.
- `scripts/build_evidence_manifest.py` today regenerates rule / compiled / fixture rows and
  preserves only `ci-run` rows; it must learn to preserve the VM evidence types before the first
  row is added. That code change lands with the first evidence.
- The `catalog` job in `.github/workflows/quality.yml` inverts `--require-validated`, and
  `tests/test_catalog.py::test_vm_validated_gate_is_still_enforced` asserts the same. Remove
  both in the commit that promotes the **last** rule; a partial promotion keeps them.
- Write-ups: replace "Not yet run against telemetry generated on a real host" with the run date
  and evidence IDs. The README coverage table, `docs/assets/status-matrix.svg` and
  `docs/index.html` regenerate from the catalog.

## Test records

### DET-001 — T1059.001 PowerShell (encoded command, or hidden window + download cradle)

- ATT&CK technique and version: T1059.001, Enterprise ATT&CK v19.2, accessed 2026-08-29.
- Atomic tests (catalog accessed 2026-08-29; upstream commit recorded at run time):
  - `a538de64-1c74-46ed-aa60-b995ed302598` (test 17, `powershell.exe -e <encoded>`) — positive.
  - `86a43bad-12e3-4e85-b97c-4d5cf25b95c3` (test 15, `-EncodedCommand` prefix variations) —
    positive; exercises the `-e` / `-ec` / `-en` / `-enc` selectors.
  - `f3132740-55bc-48c4-bcc0-758a459cd027` (test 1, IEX / DownloadString cradle) — **command
    shape only.** The upstream test fetches Invoke-Mimikatz from the internet; run the same
    command line against a harmless script served from the lab host on the host-only network
    (for example `hello.ps1`, which prints a string). Never fetch the upstream payload.
- Required privileges: standard user.
- Prerequisites: none for tests 15 and 17; a local HTTP server on the lab host for the cradle
  shape.
- Expected source events: Sysmon EventID 1 for `powershell.exe` with the full command line
  (`process.executable`, `process.command_line`). PowerShell 4104 script-block events may appear
  and are not used by this rule.
- Network access: the cradle shape reaches only the lab-served URL; nothing else.
- Cleanup: none (the commands print a string); delete `hello.ps1` from the guest if it was saved.
- Negative control (matches `FIX-DET-001-NEG`): `powershell.exe -ExecutionPolicy Bypass -File
  C:\ProgramData\Maint\cleanup.ps1` (maintenance-script shape) and an interactive
  `powershell.exe -Command "1 -eq 1"` (the ` -eq ` case that must not trigger ` -e `). Expected:
  no hit.
- Case variant: the uppercase `-ENC` shape is expected to hit on the lab index mapping and to miss
  on the stock `wildcard` mapping; record which mapping the ingest path used.
- VM snapshot, positive-test window, operator review: **not run.**

### DET-002 — T1003.001 LSASS Memory (comsvcs MiniDump or ProcDump)

- ATT&CK technique and version: T1003.001, Enterprise ATT&CK v19.2, accessed 2026-08-29.
- Atomic tests:
  - `2536dee2-12fb-459a-8c37-971844fa73be` (test 2, comsvcs.dll `MiniDump` via rundll32) —
    positive.
  - `0be2230c-9ab3-4ac2-8826-3199b9a0ebf8` (test 1, ProcDump `-ma` of lsass) — positive.
  - `7cede33f-0acd-44ef-9774-15511300b24b` (test 9, ProcDump `-mm` of lsass) — positive.
- Required privileges: local Administrator from an elevated prompt (SeDebugPrivilege).
- Prerequisites: Sysinternals ProcDump staged in the guest before it goes offline; the upstream
  test downloads it — do not let it.
- Expected source events: Sysmon EventID 1 for `rundll32.exe` / `procdump.exe` with the command
  line. Sysmon 10 (process access to lsass) and Sysmon 11 (the dump file) are expected alongside;
  keep them — they feed the Sysmon-10 variant in `docs/future-work.md` — but this rule does not use
  them.
- Network access: none.
- Cleanup: delete the dump file(s) per the upstream `cleanup_command`. The dump holds the guest's
  credentials: never copy it off the VM, never hash it into evidence; the evidence is the Sysmon
  events. Revert the snapshot after export.
- Negative control (matches `FIX-DET-002-NEG`): `procdump.exe -ma notepad.exe C:\Temp\notepad.dmp`
  and `rundll32.exe C:\Windows\System32\comsvcs.dll, Sysdiag` (comsvcs without `MiniDump`).
  Expected: no hit.
- Note: Defender may block the comsvcs dump. A blocked test whose process-creation event was
  still logged is still a positive for this rule (the command line exists); record what happened.
- VM snapshot, positive-test window, operator review: **not run.**

### DET-003 — T1053.005 Scheduled Task (SYSTEM, or user-writable path / script host)

- ATT&CK technique and version: T1053.005, Enterprise ATT&CK v19.2, accessed 2026-08-29.
- Atomic tests:
  - `fec27f65-db86-4c2d-b66c-61945aee87c2` (test 1, startup-script task with a `cmd.exe` action,
    `/ru system` shape) — positive.
  - `42f53695-ad4a-4546-abb6-7d837f644a71` (test 2, `/Create /SC ONCE`) — positive when the task
    action is a script host or a user-writable path; check the upstream default action at run time
    and set the input argument accordingly.
- Required privileges: Administrator for `/ru system`; standard user for the ONCE task.
- Prerequisites: none.
- Expected source events: Sysmon EventID 1 for `schtasks.exe` with the command line. Security 4698
  if Other Object Access auditing is on (capture it; it is the future-work logsource).
- Network access: none.
- Cleanup: `schtasks /delete /tn <task name> /f` for each task created.
- Negative control (matches `FIX-DET-003-NEG`): `schtasks /create /tn "VendorUpdate" /tr
  "C:\Program Files\Vendor\update.exe" /sc daily /st 03:00` — an installer shape without `/ru
  system` and outside the user-writable paths. Expected: no hit.
- Case variant: upstream test 2 uses `/Create`; expected to hit on the lab mapping, a known miss on
  the stock mapping. Record which applied.
- VM snapshot, positive-test window, operator review: **not run.**

### DET-004 — T1547.001 Run keys (user-writable path or script host as value data)

- ATT&CK technique and version: T1547.001, Enterprise ATT&CK v19.2, accessed 2026-08-29.
- Atomic tests:
  - `e55be3fd-3521-4610-9d1a-e210e42dcf05` (test 1, Reg Key Run) — positive **only with the
    `command_to_execute` input set to a path under `%APPDATA%`.** The upstream default
    (`C:\Path\AtomicRedTeam.exe`) would not fire and should not; run it once as an extra negative.
  - `eb44f842-0457-4ddc-9b92-c4caa144ac42` (test 3, PowerShell Registry RunOnce with a PowerShell
    command as value data) — positive.
- Required privileges: standard user (HKCU keys).
- Prerequisites: a Sysmon configuration whose RegistryEvent rules cover the Run / RunOnce keys.
  Without them no EventID 13 is generated, and an absent alert is a sensor-configuration finding,
  not a rule result.
- Expected source events: Sysmon EventID 13 with `TargetObject` under
  `...\CurrentVersion\Run\` or `RunOnce\` and `Details` = the value data; Sysmon EventID 1 for
  `reg.exe` / `powershell.exe`.
- Network access: none.
- Cleanup: remove the created values per the upstream `cleanup_command` (`reg delete` /
  `Remove-ItemProperty`).
- Negative control (matches `FIX-DET-004-NEG`): the same AppData value written under a non-Run
  key (`HKCU\Software\Vendor\Settings`), plus the upstream default-path run. Expected: no hit.
- LogScale: recorded gap (no `registry_set` mapping); the VM run does not change it.
- VM snapshot, positive-test window, operator review: **not run.**

### DET-005 — T1021.001 RDP logon from outside the documented jump hosts

- ATT&CK technique and version: T1021.001, Enterprise ATT&CK v19.2, accessed 2026-08-29.
- Atomic test: `355d4632-8cb9-449d-91ce-b566d0253d3e` (test 1, RDP to a target; the 4624
  LogonType 10 lands on the **target**) — positive. In the lab the target is the Windows guest and
  the source is a second guest or the lab host on the host-only network; no domain controller is
  needed, the event shape is the same for a local account.
- Required privileges: an account permitted to RDP on the target; NLA on.
- Prerequisites: RDP enabled on the target guest (a lab-only change made after the
  `sensors-installed` snapshot and recorded); the source assigned a non-jump address (for
  example `10.10.30.10`) for the positive run.
- Expected source events: Security 4624 with `LogonType` 10 and `IpAddress` = the source. A 4624
  LogonType 3 (NLA pre-authentication) precedes it and must not fire; 4778 may appear.
- Network access: host-only network only.
- Cleanup: log off the RDP session; revert the snapshot (which also removes the RDP enablement).
- Negative control (matches `FIX-DET-005-NEG`): the same logon with the source assigned a
  documented jump-host address (`10.10.20.5`), and a console logon (`IpAddress` `-`, no
  `source.ip` after ingest). Expected: no hit.
- LogScale: recorded gap (no Security 4624 mapping); unchanged by the run.
- VM snapshot, positive-test window, operator review: **not run.**

## Stop conditions

Do not run a test if its payload, external access, privilege requirement, cleanup, or rollback
behaviour is unclear. Never substitute the host machine for the disposable test VM. Never let a
test download anything; stage prerequisites while the guest is still on a snapshot you will
revert. Never publish raw exports, dump files, or anything derived from them.
