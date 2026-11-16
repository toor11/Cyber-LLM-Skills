# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`mqtt-and-coap-broker-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `mosquitto_sub` | `mosquitto_sub -h H -p 8883 -u U -P P -t '#' -v` | What a client can subscribe to | Mosquitto clients |
| `mosquitto_pub` | `mosquitto_pub -h H -t TOPIC -m MSG` | Whether a client can write outside its scope | Mosquitto clients |
| `coap-client` | `coap-client -m get coap://HOST/.well-known/core` | CoAP resource enumeration | libcoap |
| `openssl` | `openssl s_client -connect H:8883` | Whether the broker's TLS requires a client certificate | OpenSSL |
| `nmap` | `nmap -p 1883,8883,5683,5684 --script mqtt-subscribe H` | Broker discovery and anonymous-subscribe check | nmap |

## Minimal script shape

```python
# Classify broker posture from a configuration file and a live check.
import re
from dataclasses import dataclass

CONF = {
    "anonymous": re.compile(r"allow_anonymous\s+true", re.I),
    "no_password_file": re.compile(r"#\s*password_file|^\s*$", re.M),
    "wildcard_acl": re.compile(r"^topic\s+(readwrite|write|read)\s+#", re.M),
    "unfiltered_bridge": re.compile(r"^topic\s+#\s+both", re.M),
}

@dataclass
class Posture:
    anonymous: bool
    wildcard_acl: bool
    unfiltered_bridge: bool
    per_client_pattern: bool

def classify(config_text: str, acl_text: str) -> Posture:
    return Posture(
        anonymous=bool(CONF["anonymous"].search(config_text)),
        wildcard_acl=bool(CONF["wildcard_acl"].search(acl_text)),
        unfiltered_bridge=bool(CONF["unfiltered_bridge"].search(config_text)),
        per_client_pattern=bool(re.search(r"^pattern\s+readwrite\s+\S*%u", acl_text, re.M)),
    )

if __name__ == "__main__":
    print(classify(open("mosquitto.conf").read(), open("acl").read()))
```

`anonymous` or `wildcard_acl` true is the finding; `per_client_pattern` true is the control and belongs in the non-findings with the pattern line quoted.
