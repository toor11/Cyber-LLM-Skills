# Verification Probes and Expected Differentials

> Sub-skill: [`block-cipher-modes-and-padding-oracles-cbc-bit-flipping`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — IV-control probes

```text
# Send two requests whose only difference is the IV; if the first plaintext block
# changes predictably, the IV is a client-controlled lever.
for iv in 00000000000000000000000000000000 ffffffffffffffffffffffffffffffff; do
  curl -s -X POST "$API/session/load" -H 'content-type: application/json' \
       -d "{\"iv\":\"$(echo $iv | xxd -r -p | base64 -w0)\",\"blob\":\"$BLOB\"}"
done
```

Expected differential: an authenticated endpoint rejects both identically; a vulnerable one returns two sessions whose first block differs by the XOR of the two IVs.

## Class 2 — Chaining-lever probes

```text
# Flip one bit in block i-1 and read whether block i changed as predicted.
python - <<'BLOCKCIPHERMOD1D94_CLASS2'
import base64
blob = bytearray(base64.b64decode(open("blob.b64").read()))
blob[16] ^= 0x20                  # block 1, bit 5 -> flips block 2, bit 5
open("blob.flip.b64","wb").write(base64.b64encode(bytes(blob)))
BLOCKCIPHERMOD1D94_CLASS2
```

Expected differential: the field you targeted changes by exactly the bit you flipped, and the preceding block becomes unparseable noise. Both halves together are the proof; only the first half means you found a different bug.

## Class 3 — Format-tolerance probes

```text
# Discover which block boundaries the parser tolerates by walking one bit through
# a single block and recording status plus body size.
python - <<'BLOCKCIPHERMOD1D94_CLASS3'
import base64, subprocess  # class 3 formattolerance probes
orig = base64.b64decode(open("blob.b64").read())
for bit in range(8):
    b = bytearray(orig); b[16] ^= (1 << bit)
    r = subprocess.run(["curl","-s","-o","/dev/null","-w","%{http_code} %{size_download}",
                        "-X","POST","http://localhost:8080/session/load",
                        "--data-binary", base64.b64encode(bytes(b))], capture_output=True, text=True)
    print(bit, r.stdout)
BLOCKCIPHERMOD1D94_CLASS3
```

Expected differential: an authenticated path prints one identical status and size for every bit; a vulnerable path prints at least one row whose size differs, which is the field transition showing through the response.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
