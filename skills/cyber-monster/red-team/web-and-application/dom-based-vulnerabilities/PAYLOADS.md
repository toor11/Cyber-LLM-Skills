# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`dom-based-vulnerabilities`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `dom-based-vulnerabilities`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Source-to-sink trace (static)

**Expected differential:** a source read flows to a sink in the bundle versus terminating in a safe operation

```text
rg -n 'location\.(hash|search)|document\.referrer|\.data' app.js  (list DOM sources)
rg -n 'innerHTML|document\.write|eval\(|\.href *=' app.js  (list DOM sinks)
```

### innerHTML sink probe (live DOM)

**Expected differential:** an inert tag in the fragment becomes a DOM node versus appearing as text

```text
#zzd4k<u>probe</u>  (fragment source into an innerHTML sink)
?view=zzd4k<u>probe</u>  (query source into an innerHTML sink)
```

### Navigation/redirect sink probe

**Expected differential:** a scheme in the source changes the location assignment target versus being treated as a path

```text
#next=https://<assessor-controlled-host>/zzd4k  (location assignment from fragment)
?return=//<assessor-controlled-host>/zzd4k  (scheme-relative redirect source)
```

### postMessage origin probe

**Expected differential:** a handler acts on message data from an arbitrary origin versus rejecting it

```text
window.postMessage('zzd4k-probe','*')  (observe if a handler consumes cross-origin data)
rg -n 'addEventListener\("message"' app.js  (find handlers missing event.origin checks)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
