# Alert enrichment workflow

The automation component demonstrates a small SOAR-style contract without claiming to replace an incident-response platform.

## Input

- Detection ID and title
- Host and user identifiers
- Original rule severity and confidence
- ATT&CK mappings
- Asset criticality and identity privilege context

## Processing

1. Validate required fields.
2. Add static asset/user context from synthetic fixtures.
3. Compute a transparent priority score.
4. Attach a human-readable reason list and recommended first checks.
5. Preserve the original alert and enrichment version.

## Output

An analyst-ready record suitable for a ticket or webhook. The workflow must not automatically contain, disable, or block an account in this portfolio.

