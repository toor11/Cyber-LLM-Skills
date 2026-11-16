# Verification Probes and Expected Differentials

> Sub-skill: [`mqtt-and-coap-broker-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Authentication gate

```text
# Anonymous connect attempt, then an authenticated one.
mosquitto_sub -h "$BROKER" -p 1883 -t 'test' -C 1 -W 2; echo "exit=$?"
mosquitto_pub -h "$BROKER" -p 1883 -t 'test' -m 'probe'
```

Expected differential: a `Connection Refused: not authorised` is the control; a successful subscribe or publish with no credentials is the finding.

## Class 2 — Namespace enumeration

```text
# What does one client see on a wildcard subscribe?
timeout 10 mosquitto_sub -h "$BROKER" -p 1883 -u "$USER" -P "$PASS" -t '#' -v | head -20
# CoAP discovery for the equivalent.
coap-client -m get "coap://$HOST/.well-known/core"
```

Expected differential: the client's own topics only is the control; other devices' or tenants' topics in the output is the finding, and the topic names are the evidence.

## Class 3 — Write-scope probe

```text
# Can the client publish outside its own prefix? Use a lab topic, never an actuator.
mosquitto_pub -h "$BROKER" -u "$USER" -P "$PASS" -t "devices/other-device/cmd" -m '{"probe":1}'
```

Expected differential: a rejection or a silent drop is the control; delivery to the other device's topic is the finding, and the ACL entry that allowed it is the citation.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
