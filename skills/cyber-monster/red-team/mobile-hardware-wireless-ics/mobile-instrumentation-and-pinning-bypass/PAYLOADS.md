# Verification Probes and Expected Differentials

> Sub-skill: [`mobile-instrumentation-and-pinning-bypass`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Mechanism classification

```text
# Where does pinning live?
rg -n --no-heading "<pin-set|<pin " app/src/main/res/xml/
rg -n --no-heading "CertificatePinner|certificatePinner|TrustKit|didReceive challenge" app/src/ ios/
# And integrity checks:
rg -n --no-heading "isRooted|SafetyNet|PlayIntegrity|DeviceCheck|attestKey|jailbreak" app/src/ ios/
```

Expected differential: `<pin-set>` in the config or a `didReceive challenge` implementation is platform-enforced; a string comparison in a ViewModel is removable, and the two are reported differently.

## Class 2 — Interception differential (lab only)

```text
# Baseline: direct request. Probe: same request through a lab proxy with a user CA.
curl -s -o /dev/null -w 'direct: %{http_code}\n' https://api.example.com/v1/health
HTTPS_PROXY=http://127.0.0.1:8080 curl -s -o /dev/null -w 'proxied: %{http_code}\n' https://api.example.com/v1/health
# Then the same from the app build in a lab device, checking whether traffic appears in the proxy log.
```

Expected differential: the proxied request failing while the direct one succeeds indicates pinning or a pin-set; traffic appearing in the proxy log for the app means no enforcement, and the report states what the captured requests contain.

## Class 3 — Server-side attestation check

```text
# Does the server verify an assertion, or does it trust a client boolean?
rg -n --no-heading "attest|assertion|integrity|nonce" server/ | head -20
rg -n --no-heading "isRooted|rooted" server/ || echo "server never sees a rooted flag"
```

Expected differential: a server route that validates a signed assertion against a nonce is the control; a route that branches on a client-supplied boolean is the finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
