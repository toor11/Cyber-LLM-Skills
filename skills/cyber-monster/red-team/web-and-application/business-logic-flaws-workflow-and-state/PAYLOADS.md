# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`business-logic-flaws-workflow-and-state`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `business-logic-flaws-workflow-and-state`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Step-skip probe

**Expected differential:** calling the gated transition before its prerequisite persists the advanced state versus the in-order run which refuses it; read the record server-side

```text
POST /checkout/confirm after /cart only (skip /payment), read order status
POST /withdrawal/approve before /kyc/submit, read case status
```

### Client-forced status

**Expected differential:** submitting a target status directly advances the record versus omitting it, proving caller-named state is trusted

```text
status=verified  (client-forced on profile write)
workflow_step=complete  (client-forced on process write)
```

### One-time step replay

**Expected differential:** replaying a completed step compounds its effect (second credit, second approval) versus a single call

```text
replay POST /invite/accept with the same token twice
replay POST /reward/claim for one completed milestone twice
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
