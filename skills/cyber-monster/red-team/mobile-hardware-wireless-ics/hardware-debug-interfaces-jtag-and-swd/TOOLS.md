# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`hardware-debug-interfaces-jtag-and-swd`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `openocd` | `openocd -f interface/cmsis-dap.cfg -f target/X.cfg -c "init; dap info; shutdown"` | Whether the transport responds and what it identifies | OpenOCD |
| `pyocd` | `pyocd list --targets` then `pyocd cmd -t TARGET` | An alternative transport stack that reports locked devices clearly | Python |
| `minipro` | `minipro -p CHIP -r dump.bin` | Whether the external flash is protected, independent of the SoC | minipro |
| `JLinkExe` | `JLinkExe -device X -if SWD -speed 4000` | Vendor transport with explicit locked-device messages | SEGGER |
| `rg` | `rg -a -e 'dbg_key' -e 'debug_key' firmware.bin` | Whether the authentication key is in the image | any |

## Minimal script shape

```python
# Classify a debug transport from openocd's output.
import subprocess

def probe(interface: str, target: str) -> dict:
    out = subprocess.run(["openocd", "-f", interface, "-f", target,
                          "-c", "init; dap info; shutdown"],
                         capture_output=True, text=True)
    text = out.stdout + out.stderr
    return {"tap_enabled": "tap/device found" in text or "SW-DP ID" in text,
            "locked": "got 0x00000000" in text or "not examined" in text,
            "excerpt": text.strip().splitlines()[-3:]}

if __name__ == "__main__":
    print(probe("interface/cmsis-dap.cfg", "target/stm32f4x.cfg"))
```

`tap_enabled: False` with `locked: True` is the control; `tap_enabled: True` means the guard question moves to debug authentication and read-out protection.
