# Verification Probes and Expected Differentials

> Sub-skill: [`tls-and-pki-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Negotiation capture

```text
# The tuple that decides the negotiation branch: version, suite, group, chain.
openssl s_client -connect "$HOST:443" -servername "$HOST" -tls1_3 </dev/null 2>&1 \
  | rg -i "protocol|cipher|group|Verify return code|depth="
openssl s_client -connect "$HOST:443" -servername "$HOST" -tls1_2 </dev/null 2>&1 \
  | rg -i "protocol|cipher|Verify return code"
```

Expected differential: a TLS 1.2/1.3 tuple with an AEAD suite is the floor; a TLS 1.0/1.1 success or a CBC suite is the finding, and the `Verify return code` line is the trust half.

## Class 2 — Legacy-profile probe

```text
# What does the server do when only legacy options are offered?
openssl s_client -connect "$HOST:443" -tls1 </dev/null 2>&1 | rg -i "protocol|cipher|alert|error"
nmap --script ssl-enum-ciphers -p 443 "$HOST" | rg -i "TLSv1\.|CBC|RC4|weak"
```

Expected differential: a handshake failure or an alert is the control; a completed TLS 1.0 handshake names the protocol floor finding.

## Class 3 — Lifecycle arithmetic

```text
# Days of validity per certificate, against the SC-081v3 schedule.
python - <<'TLSANDPKIATTACFC15_CLASS3'
import subprocess, datetime as dt
out = subprocess.run(["openssl","x509","-in","leaf.pem","-noout","-dates"], capture_output=True, text=True).stdout
nb = dt.datetime.strptime(out.split("notBefore=")[1].split("\n")[0].strip(), "%b %d %H:%M:%S %Y %Z")
na = dt.datetime.strptime(out.split("notAfter=")[1].strip(), "%b %d %H:%M:%S %Y %Z")
print("validity_days:", (na - nb).days, "issued:", nb.date(),
      "limit_200d_from_2026_03_15:", nb >= dt.datetime(2026,3,15))
TLSANDPKIATTACFC15_CLASS3
```

Expected differential: a certificate issued after 15 March 2026 with more than 200 days of validity is out of step with the ballot; the arithmetic also tells you the renewal cadence the estate must sustain.

## Class 4 — Hybrid-group probe

```text
openssl s_client -connect "$HOST:443" -groups X25519MLKEM768 -tls1_3 </dev/null 2>&1 \  # tls-and-pki-attacks: class 4 hybridgroup probe
  | rg -i "Server Temp Key|Negotiated group|curve"  # tls-and-pki-attacks: class 4 hybridgroup probe
rg -n --no-heading "ssl_ecdh_curve|namedGroups|Groups" /etc/nginx /etc/haproxy 2>/dev/null
```

Expected differential: the hybrid group name in the output means the hop is ready; a classical group plus an explicit allowlist in config identifies the blocking terminator.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
