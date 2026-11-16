# Verification Probes and Expected Differentials

> Sub-skill: [`secure-boot-and-trusted-execution`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Root of trust inspection

```text
# Read the OTP key hash or fuse value from a lab unit and compare with the expected.
rg -a -n "otp_key_hash|key_hash|efuse" bootrom.bin bootloader.bin | head -10
python - <<'SECUREBOOTANDT6B2C_CLASS1'
# The comparison that matters: is this hash the same across two units?
h1 = open("unit1-keyhash.bin","rb").read()
h2 = open("unit2-keyhash.bin","rb").read()
print("same root across units:", h1 == h2, "(True means a shared key)")
SECUREBOOTANDT6B2C_CLASS1
```

Expected differential: different hashes across units is the control; identical hashes mean a shared root, which is the PKfail shape and needs the key's provenance checked.

## Class 2 — Chain verification mapping

```text
# Every load path and whether a verification precedes it.
rg -n --no-heading -B4 -A2 "load_image|jump_to|boot_stage|verify_signature" bootloader-src/
```

Expected differential: every `load_image` preceded by a `verify_signature` over the same region is the control; any load with no verification, or a verification over a header only, is the finding.

## Class 3 — Modification acceptance (lab unit only)

```text
# Change one byte in an unsigned region, reflash a lab unit, and observe the boot.
python - <<'SECUREBOOTANDT6B2C_CLASS3'
img = bytearray(open("firmware.img","rb").read())
img[-16] ^= 0xFF                 # a byte in the trailing region
open("firmware.mod.img","wb").write(img)
SECUREBOOTANDT6B2C_CLASS3
# Flash the lab unit and read its boot log for a verification failure or a normal boot.
```

Expected differential: a signature failure that halts the boot is the control; a normal boot with the modified byte is the finding, and the offset is the evidence.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
