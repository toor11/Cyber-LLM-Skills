# Verification Probes and Expected Differentials

> Sub-skill: [`tls-and-pki-attacks-configuration-weaknesses`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Protocol and suite enumeration

```text
# What will the server accept, at its weakest?
nmap --script ssl-enum-ciphers -p 443 "$HOST" | rg -i "TLSv1\.|CBC|RC4|3DES|weak|strong"
```

Expected differential: a list containing only TLS 1.2/1.3 with AEAD suites is the control; any TLS 1.0/1.1 or CBC/static-RSA entry is the finding, named individually.

```text
# Per-protocol confirmation with a direct handshake.
for v in -tls1 -tls1_1 -tls1_2 -tls1_3; do
  printf '%-8s ' "$v"
  openssl s_client -connect "$HOST:443" -servername "$HOST" $v </dev/null 2>&1 \
    | rg -m1 "Protocol\s*:|alert|handshake failure" || echo "no handshake"
done
```

## Class 2 — Curve-allowlist probe

```text
# Is an explicit allowlist overriding the library default?
rg -n --no-heading "ssl_ecdh_curve|namedGroups|Groups\s*=|curves\s*=" /etc 2>/dev/null
openssl s_client -connect "$HOST:443" -groups X25519MLKEM768 -tls1_3 </dev/null 2>&1 \  # tls-and-pki-attacks-configuration-weaknesses: class 2 curveallowlist probe
  | rg -i "Server Temp Key|Negotiated group|curve"  # tls-and-pki-attacks-configuration-weaknesses: class 2 curveallowlist probe
```

Expected differential: the hybrid group negotiated means no blocking allowlist; a classical group plus an allowlist line identifies the exact config responsible.

## Class 3 — Extension probes

```text
# Compression and renegotiation state, which are separate findings.
openssl s_client -connect "$HOST:443" -servername "$HOST" -reconnect </dev/null 2>&1 \
  | rg -i "Compression|Secure Renegotiation|renegotiat"
```

Expected differential: `Compression: NONE` and `Secure Renegotiation IS supported` are the controls; `Compression: zlib` or an insecure renegotiation banner is a finding with its own proof.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
