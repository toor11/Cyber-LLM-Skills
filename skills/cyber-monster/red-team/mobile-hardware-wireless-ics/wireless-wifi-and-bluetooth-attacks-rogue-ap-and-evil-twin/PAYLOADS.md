# Verification Probes and Expected Differentials

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Client validation configuration

```text
# What does the supplicant validate?
rg -n --no-heading "ca_cert|domain_suffix_match|domain_match|subject_match|phase2" /etc/wpa_supplicant/ /etc/NetworkManager/system-connections/ 2>/dev/null
wpa_cli -i wlan0 status | rg -i "key_mgmt|ssid|supplicant"
```

Expected differential: `ca_cert` plus `domain_suffix_match` is the control; neither present on a corporate SSID is the finding, and the profile file is the citation.

## Class 2 — Twin acceptance probe (lab only)

```text
# A lab AP with the same SSID and a self-signed certificate for the radius domain.
hostapd -B lab-twin.conf
# Then, on a lab client with the corporate profile, watch whether the outer TLS
# handshake completes and whether an inner identity is sent.
journalctl -u wpa_supplicant -f | rg -i "TLS|EAP|identity"
```

Expected differential: a certificate-validation failure that aborts the association is the control; the inner identity appearing in the log is the finding, and the report never includes the credential.

## Class 3 — PMF state

```text
tshark -r cap.pcapng -Y "wlan.fc.type_subtype == 8" -T fields -e wlan.ssid -e wlan.rsn.capabilities.mfpr -e wlan.rsn.capabilities.mfpc  # wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin: class 3 pmf state
tshark -r cap.pcapng -Y "wlan.fc.type_subtype == 12" -c 5    # deauth frames
```

Expected differential: `mfpr` set means deauth frames are ignored, which is the control; deauth frames present and effective means the forcing mechanism works.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
