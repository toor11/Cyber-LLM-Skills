# Verification Probes and Expected Differentials

> Sub-skill: [`tls-and-pki-attacks-certificate-validation-gaps`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Trust-decision inventory

```text
# Every place a trust decision is made or disabled.
rg -n --no-heading "verify\s*=\s*False|InsecureSkipVerify|CERT_NONE|checkServerTrusted|HostnameVerifier|setHostnameVerifier" -g '!test*'
rg -n --no-heading "create_default_context|truststore|ca_bundle|--cacert" -g '!test*'
```

Expected differential: a default context with no override is a control; any of the first group is the finding, subject to reachability.

## Class 2 — Wrong-name probe

```text
# Does the client accept a certificate for a different name? Lab endpoint only.
openssl s_server -accept 8443 -cert wrong-name.pem -key wrong-name.key -www &
python - <<'TLSANDPKIATTACD0DC_CLASS2'
import ssl, socket
ctx = ssl.create_default_context(cafile="lab-ca.pem")
try:
    with socket.create_connection(("127.0.0.1", 8443)) as s:
        with ctx.wrap_socket(s, server_hostname="api.example.com") as t:
            print("ACCEPTED wrong-name certificate -> validation gap")
except ssl.SSLCertVerificationError as e:
    print("rejected:", e.verify_message)
TLSANDPKIATTACD0DC_CLASS2
```

Expected differential: `SSLCertVerificationError` with a hostname message is the control; a completed handshake is the finding.

## Class 3 — Pin-field probe

```text
# Which field does the pin compare? Subject and serial pins do not survive reissue.
rg -n --no-heading -A4 "pin|pinSha256|EXPECTED_SPKI|certificatePinner" -g '!test*'
```

Expected differential: a pin over `sha256(SPKI)` is effective; a comparison against `subjectDN`, `serialNumber`, or the whole DER certificate is either ineffective against reissue or brittle against renewal.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
