# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`business-logic-flaws-workflow-and-state`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: AVideo: Video Publishing Workflow Bypass via Unauthorized overrideStatus Request Parameter

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-840`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary AVideo's video processing pipeline accepts an 'overrideStatus' request parameter that allows any uploader to set a video's status to any valid state, including "active" ('a'). This bypasses the admin-controlled moderation and draft workflows. The 'setStatus()' method v
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: AVideo: Video Publishing Workflow Bypass via Unauthorized overrideStatus Request Parameter

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-840`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # AVideo: Video Publishing Workflow Bypass via Unauthorized overrideStatus Request Parameter AVideo: Video Publishing Workflow Bypass via Unauthorized overrideStatus Request Parameter - **OSV ID**: GHSA-m577-w9j8-ch7j - **CVE**: CVE-2026-34738 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
