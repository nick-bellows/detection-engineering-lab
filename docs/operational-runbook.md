# Detection operational runbook

## Change workflow

1. Create or update the Sigma source rule.
2. Record the reason and expected behavior change.
3. Run static validation.
4. Replay sanitized positive and negative fixtures.
5. Translate to the selected SIEM backend and inspect the query.
6. Rerun the controlled VM test when source telemetry assumptions changed.
7. Update the writeup, catalog, and validation matrix.

## Alert-quality review

- Required analyst context is present.
- Severity and confidence are separate concepts.
- Rule name states behavior, not a conclusion about intent.
- Triage steps can confirm or reject the hypothesis.
- Known administrative workflows are documented.

## Retirement

Retire rather than silently delete a detection. Record its replacement, reason, last validated version, and any coverage gap introduced.

