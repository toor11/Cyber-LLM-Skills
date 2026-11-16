# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`hardware-debug-interfaces-uart-and-serial`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `miniterm` | `python -m serial.tools.miniterm --rts 0 --dtr 0 /dev/ttyUSB0 115200` | Interactive console with flow control disabled, which matters on 3-wire setups | pyserial |
| `picocom` | `picocom -b 115200 --omap crlf /dev/ttyUSB0` | Alternative console client with explicit line-ending mapping | POSIX |
| `sigrok`/`pulseview` | `sigrok-cli -d fx2lafw --config samplerate=1m -o capture.sr` | Logic capture for baud measurement and pin identification | sigrok |
| `strings` | `strings -a boot.log` | Secret scan of the captured log | POSIX |
| `binwalk` | `binwalk -e firmware.bin` | Extracting the bootloader configuration to confirm the console setting offline | POSIX |

## Minimal script shape

```python
# Capture a boot log, flag interactivity and secrets, and record the guard lines.
import re
import serial

SECRETS = re.compile(r"(passw(or)?d\s*=\s*\S+|api[_-]?key\s*=\s*\S+|wpa_passphrase=\S+)", re.I)
GUARDS = re.compile(r"(verified|Verified|signature|init=/bin/sh|Hit any key)", re.I)

def capture(port: str, baud: int, seconds: float = 40) -> dict:
    s = serial.Serial(port, baud, timeout=0.5)
    log, interactive = [], False
    for _ in range(int(seconds * 2)):
        chunk = s.read(8192)
        if not chunk:
            continue
        text = chunk.decode(errors="replace")
        log.append(text)
        if "Hit any key" in text:
            s.write(b" ")
    joined = "".join(log)
    return {"secrets": SECRETS.findall(joined),
            "guards": sorted(set(GUARDS.findall(joined))),
            "prompt_seen": bool(re.search(r"(=>|#|login:)\s*$", joined, re.M))}

if __name__ == "__main__":
    print(capture("/dev/ttyUSB0", 115200))
```

`secrets` non-empty is a finding regardless of interactivity; `prompt_seen` with no `verified` guard is the shell finding.
