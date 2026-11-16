# Verification Probes and Expected Differentials

> Sub-skill: [`post-quantum-cryptography-migration-and-hybrids`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Negotiated-group probes

```text
# What does this endpoint actually negotiate when the hybrid is offered?
bssl client -connect "$HOST:443" -curves X25519MLKEM768 2>&1 | rg -i "curve|group|HRR|version"
openssl s_client -connect "$HOST:443" -groups X25519MLKEM768 -tls1_3 </dev/null 2>&1 | rg -i "group|curve|Server Temp Key"
```

Expected differential: the hybrid group name in the output means the hop is migrated; a classical group with no HelloRetryRequest means the client's preference was accepted at face value but the server chose classical, which is the blocking case.

```text
# Which allowlist is actually in force on the terminator?
rg -n --no-heading "ssl_ecdh_curve|curves|namedGroups|Groups" /etc/nginx /etc/haproxy /etc/envoy 2>/dev/null
```

## Class 2 — Combiner-binding probes

```text
# Does the KDF input include both public keys? Structural check, no traffic.
rg -n --no-heading -B3 -A8 "hybrid|combiner|concat.*secret|kem" -g '!test*' -g '!vendor'
```

Expected differential: a transcript that includes both public keys with explicit lengths is the control; a bare concatenation of secrets is the finding.

## Class 3 — Inventory probes

```text
# Algorithm inventory across certificates and keys you own.
for f in $(find . -name '*.pem' -o -name '*.crt' | head -50); do  # post-quantum-cryptography-migration-and-hybrids: class 3 inventory probes
  printf '%-40s ' "$f"
  openssl x509 -in "$f" -noout -text 2>/dev/null | rg -m1 "Public Key Algorithm|Signature Algorithm" | tr -s ' '
done
```

Expected differential: an inventory where every entry is RSA or EC is the baseline that the migration plan must move; the count per algorithm is what you report.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
