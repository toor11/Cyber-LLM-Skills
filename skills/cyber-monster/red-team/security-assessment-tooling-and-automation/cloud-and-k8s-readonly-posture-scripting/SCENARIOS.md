# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cloud-and-k8s-readonly-posture-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Clean Report From a Blind Collector

- **Surface & Preconditions:** A posture script reports zero public buckets while the audit role cannot call `s3:ListBuckets`.
- **Root Cause & Impact:** The empty list is the collector's blind spot, and the report asserts a security property that was never observed.
- **Verification & Fix:** Re-run with an explicit gap list, add the missing read permission, and treat any gap as an incomplete control rather than a pass.

## Case 2: Privileged Pod Outside the Baseline

- **Surface & Preconditions:** A namespace contains a pod with `privileged: true` and a hostPath mount to the node root, with no baseline entry.
- **Root Cause & Impact:** Both properties are node-level exposure; individually they read as configuration, together they are a container escape path.
- **Verification & Fix:** Report the pod UID, the securityContext field, and the hostPath, then confirm whether the namespace is in the assessment scope.
