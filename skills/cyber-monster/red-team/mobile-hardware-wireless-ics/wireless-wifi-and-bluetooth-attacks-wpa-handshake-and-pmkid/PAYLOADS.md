# Verification Probes and Expected Differentials

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Capture classification

```text
# What is in the capture: a full handshake, a partial one, or a PMKID?
tshark -r cap.pcapng -Y "eapol" -T fields -e eapol.type -e wlan.ra -e wlan.ta | head -10
hcxpcapngtool -o out.hc22000 cap.pcapng 2>&1 | rg -i "handshakes|PMKID"
```

Expected differential: a PMKID or a complete handshake converts to a testable hash; `no hashes written` means the capture is not testable and the finding cannot rest on it.

## Class 2 — Entropy arithmetic

```text
python - <<'WIRELESSWIFIAN3692_CLASS2'
import math
def space(chars: int, alphabet: int) -> float:
    return chars * math.log2(alphabet)
for chars, alpha, label in ((8, 62, "8 chars mixed"), (12, 62, "12 chars mixed"),
                            (20, 62, "20 chars mixed"), (16, 26, "16 lowercase")):
    bits = space(chars, alpha)
    days = 2 ** bits / 2e6 / 86400        # 2M candidates/s as a reference rate
    print(f"{label}: {bits:.0f} bits, ~{days:.3e} days at 2e6/s")
WIRELESSWIFIAN3692_CLASS2
```

Expected differential: this is arithmetic for the report. A space that resolves to minutes or hours supports the finding; one that resolves to millennia is the non-finding, with the numbers quoted.

## Class 3 — PMF state

```text
tshark -r cap.pcapng -Y "wlan.fc.type_subtype == 8" -T fields -e wlan.ssid -e wlan.rsn.capabilities.mfpr -e wlan.rsn.capabilities.mfpc  # wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid: class 3 pmf state
```

Expected differential: `mfpr` and `mfpc` set is the control; both absent means deauthentication frames are honoured, which widens the capture window.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
