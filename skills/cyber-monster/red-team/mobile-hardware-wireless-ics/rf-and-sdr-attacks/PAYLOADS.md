# Verification Probes and Expected Differentials

> Sub-skill: [`rf-and-sdr-attacks`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Link characterisation (receive only)

```text
# Capture the same button twice and compare; identical payloads mean a fixed code.
rtl_433 -f 433.92M -A -w /tmp/cap1.cu8 &
sleep 2; echo "press the button"
sleep 4; kill %1
python - <<'RFANDSDRATTACKB50A_CLASS1'
a = open("/tmp/cap1.cu8","rb").read()
print("bytes:", len(a), "distinct_byte_values:", len(set(a)))
RFANDSDRATTACKB50A_CLASS1
```

Expected differential: a payload with a small set of symbol values and a repeated pattern is an OOK/FSK remote; high entropy with no repetition suggests a cryptographic layer.

## Class 2 — Field comparison

```text
# Decode two presses and diff the fields.
for f in press1 press2; do
  rtl_433 -r "$f.cu8" -F json 2>/dev/null | jq -c '{model,id,code,counter}'
done
```

Expected differential: identical `code` across presses is the fixed-code finding; a `counter` that increments is the rolling-code control, and the counter width bounds the acceptance window.

## Class 3 — Receiver response (shielded lab only)

```text
# Replay a recorded frame into a shielded receiver and observe the action.
python - <<'RFANDSDRATTACKB50A_CLASS3'
# Receive-only analysis path: load the recording and identify the pulse train.
raw = open("/tmp/cap1.cu8","rb").read()
print("pulse_train_len:", len(raw), "replayable:", len(set(raw)) < 8)
RFANDSDRATTACKB50A_CLASS3
# Transmission, if and only if the engagement authorises it inside an enclosure.
```

Expected differential: a receiver action on the replay is the finding; no action means the counter or the replay record rejected it, which is the control.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
