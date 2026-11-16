# Verification Probes and Expected Differentials

> Sub-skill: [`wireless-wifi-and-bluetooth-attacks`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Radio parameter inventory

```text
# Beacons with AKM suites and MFP state, from a monitor-mode capture.
tshark -r wifi.pcapng -Y "wlan.fc.type_subtype == 8" -T fields \
  -e wlan.ssid -e wlan.rsn.akms.type -e wlan.rsn.capabilities.mfpr
# Bluetooth devices and their pairing modes, from a passive scan.
bluetoothctl --timeout 20 scan on
```

Expected differential: `SAE` alone with `mfpr` set is the control; `PSK` present or `mfpr` absent is the finding, and the AKM list is the evidence.

## Class 2 — Downgrade probe (lab only)

```text
# Does the client accept a PSK association when SAE is also offered?
# On a lab AP, disable SAE and observe whether the corporate client still associates.
hostapd_cli -i wlan0 disable
hostapd_cli -i wlan0 set wpa_key_mgmt WPA-PSK
hostapd_cli -i wlan0 enable
# Then check the AP's association log for the client.
```

Expected differential: the client refusing to associate is the control; the client associating over PSK is the finding, and the association frame shows the AKM it chose.

## Class 3 — Certificate-validation check (Enterprise)

```text
# On the client, is the server certificate validated against a pinned CA?
rg -n --no-heading "ca_cert|domain_suffix_match|subject_match|tls_verify" /etc/wpa_supplicant/ 2>/dev/null
# And the effective configuration from the running supplicant:
wpa_cli -i wlan0 status | rg -i "key_mgmt|ssid"
```

Expected differential: `ca_cert` with `domain_suffix_match` present is the control; neither present means any AP with a matching SSID is accepted, which is the evil-twin finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
