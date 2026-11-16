# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`iot-thread-and-openthread-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `ot-ctl` | `ot-ctl commissioner state` | Whether a commissioner session or joiner window is active | OpenThread CLI |
| `ot-ctl` | `ot-ctl joiner port any` | The joiner port state, which gates commissioning | OpenThread CLI |
| `wireshark` | `wireshark -i mon0 -Y "wpan"` | 802.15.4 commissioning frames, for a passive view | Wireshark with a sniffer |
| `ot-br-posix` | `otbr-agent --help` | Border router features, including ePSKc support | OpenThread border router |
| `nRF Sniffer` | capture with a 802.15.4 sniffer board | Passive frame capture where no monitor interface exists | hardware sniffer |

## Minimal script shape

```python
# Classify a Thread commissioning configuration from build flags and source.
import pathlib
import re

FLAGS = {
    "tcat": "OPENTHREAD_CONFIG_BLE_TCAT_ENABLE",
    "ephemeral_key": "OPENTHREAD_CONFIG_BORDER_AGENT_EPHEMERAL_KEY_ENABLE",
}
LITERAL_PSKD = re.compile(r'otJoinerStart\([^,]+,\s*"([^"]{4,})"')

def classify(root: str) -> dict:
    flags, literals = {}, []
    for p in pathlib.Path(root).rglob("*"):
        if p.suffix not in (".h", ".c", ".cpp", ".txt", ".cmake"):
            continue
        text = p.read_text(errors="ignore")
        for name, flag in FLAGS.items():
            if flag in text:
                flags[name] = True
        literals += LITERAL_PSKD.findall(text)
    return {"features": sorted(flags), "literal_pskd": literals}

if __name__ == "__main__":
    print(classify("."))
```

A non-empty `literal_pskd` is the fleet-static finding and the literal itself is the evidence; the `features` list says whether the Thread 1.4 sharing mechanisms exist at all.
