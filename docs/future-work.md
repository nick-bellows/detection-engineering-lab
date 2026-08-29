# Future work

The single home for "what would come next". Each item names the job-description line it answers
so the list stays a backlog, not a roadmap.

| Item | What it adds | Answers |
| --- | --- | --- |
| **Atomic Red Team run in an isolated VM** (`telemetry/atomic-test-plan.md`) | Moves every rule from `fixture-validated` to `validated`: real Sysmon/Security events from the five tests, exported, sanitised, hashed into `evidence/` | "validate detections against generated telemetry" (Booz Allen Signals & Defense); "test and tune basic security detections" (CrowdStrike TIDE) |
| **DET-002 process-access variant** (Sysmon 10, lsass `GrantedAccess` allowlist) | Catches direct-syscall dumpers and Task Manager, which leave no command line | "research attacker techniques" (TIDE) |
| **Hand-written Falcon queries for DET-004/005** (`AsepValueUpdate`, `UserLogon` LogonType 10) | Closes the two LogScale gaps the pySigma Falcon pipeline cannot express | "LogScale, NGSIEM" (CrowdStrike Threat Hunter) |
| **`OriginalFileName` clause for DET-002** | Renamed ProcDump binaries | rule-bypass review question 4 |
| **Security 4698 logsource for DET-003** | Tasks created through the COM API / PowerShell cmdlets | "detection methodologies" (Threat Hunter) |
| **Startup-folder and Winlogon variants of DET-004** (Sysmon 11, `Userinit`/`Shell`) | The other half of T1547.001 | ATT&CK coverage honesty |
| **PowerShell 4104 script-block rule** | Encoded content decoded at runtime, `FromBase64String` cradles | DET-001 blind spot |
| **`ml/` authentication-anomaly baseline** (isolation forest on synthetic auth logs) | The supplementary comparison the scaffold planned; gated on `validated` per `ml/README.md` | "ML output that furthers cyber investigations" (Booz Allen Cyber ML Engineer) |
| **Kibana bootstrap** (`kibana_system` password init) | Detection-rule import of the committed `*.siem_rule.ndjson` into a real Kibana Security app | screenshot evidence for `validated` |
| **Enrichment via a real ticket/webhook sink** | Today the CLI prints the record; a SOAR-style hand-off would post it | "automate basic response workflows" (TIDE) |

Not planned: running Atomic tests outside a disposable VM, ingesting third-party telemetry
captures, or claiming production false-positive rates from synthetic data.
