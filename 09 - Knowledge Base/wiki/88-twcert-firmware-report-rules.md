---
type: wiki
category: workflow
tool: manual
status: active
last-updated: 2026-06-04
---

# TWCERT Firmware Report Writing Rules (Reference Card)

> **Purpose:** Writing TWCERT firmware vulnerability reports; any "TWCERT format" decision point.
> The existing `Reference Card - TWCERT CVE Form` only has field definitions; it does not include the writing rules accumulated after multiple user corrections.
> This card is the writing-rules layer; field definitions still follow the TWCERT CVE Form.

## Vulnerability Description

- First sentence: "[Vendor] [Model] [Version] has [vulnerability type]." **Do not add "suspected"/"appears to".**
- Do not cite internal IDs (e.g. D-001); use only the vendor/model.
- When no CVE has been assigned, write "This vulnerability has not yet been assigned a CVE ID"; **do not write "CVE-TBD"**.

## Affected Versions

- Specify with `≤` or `<`; do not use "and below" phrasing.
- The source must be an actual download / verification, not just a citation of an advisory.
- If only a single version was verified: "Verified on version X.Y.Z; other versions not confirmed."

## PoC / Reproduction Steps

- Each step on its own line, numbered.
- Paste the full `curl` command (including `-H` headers), not abbreviated.
- Response screenshots: capture only the key response, not the entire terminal.

## Impact Description

- Do not overstate attack prerequisites (e.g. if "LAN access is required," state it).
- Do not write "the attacker can fully control the device" unless there is an RCE PoC.
- Write CIA impact separately (one line each for C / I / A).

## Remediation Recommendations

- At least one actionable recommendation (not just "please have the vendor patch it").
- When referencing the remediation approach of a similar CVE, cite the CVE ID.

## Common User-Correction Pitfalls

- Do not add parenthetical clarifications in the title (use the description field instead).
- "Unauthenticated" must be verified with a PoC; it cannot be based only on "appears to have no authentication."
- If the endpoint requires login before it can be triggered: lower the severity by one level.

## Related Documents

- `09 - Knowledge Base/Reference Card - TWCERT CVE Form.md` — field definitions
- `09 - Knowledge Base/Reference Card - TWCERTCC_Vulnerability_Disclosure_Policy_v2.2.pdf`
- `09 - Knowledge Base/wiki/86-dupe-hunting-report-writing.md` — anti-overclaiming report writing
