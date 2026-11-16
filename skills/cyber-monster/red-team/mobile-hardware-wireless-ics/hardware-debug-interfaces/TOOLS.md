# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`hardware-debug-interfaces`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `miniterm` | `python -m serial.tools.miniterm /dev/ttyUSB0 115200` | Console interaction at a measured baud rate | pyserial |
| `picocom` | `picocom -b 115200 /dev/ttyUSB0` | Lighter console client with hex view | POSIX |
| `minipro` | `minipro -p "W25Q64" -r dump.bin` | Flash read for an SPI NOR chip, offline | minipro |
| `flashrom` | `flashrom -p ch341a_spi -r dump.bin` | Flash read with a common programmer | POSIX |
| `xxd` | `xxd -l 256 dump.bin` | Whether the read is ciphertext or a filesystem header | POSIX |
| `openocd` | `openocd -f interface/ftdi.cfg -f target/stm32f4x.cfg` | Debug transport access, which reports a locked TAP as an error | OpenOCD |

## Minimal script shape

```python
# Classify an interface inventory into finding / hardening note.
from dataclasses import dataclass

@dataclass
class Interface:
    name: str
    interactive: bool
    yields_memory: bool
    yields_flash: bool

@dataclass
class Guards:
    secure_boot: bool
    flash_encryption: bool
    debug_auth_locked: bool

def verdict(i: Interface, g: Guards) -> str:
    if not (i.interactive or i.yields_memory or i.yields_flash):
        return "not reachable: no interactive or read capability"
    if g.debug_auth_locked and g.secure_boot and g.flash_encryption:
        return "hardening note: interface present, guards intact"
    if i.interactive and not g.secure_boot:
        return "finding: interactive console without a secure boot chain"
    if i.yields_flash and not g.flash_encryption:
        return "finding: flash readable in plaintext"
    return "finding: partial guards, name the missing one"

if __name__ == "__main__":
    print(verdict(Interface("uart", True, False, False),
                  Guards(secure_boot=False, flash_encryption=False, debug_auth_locked=False)))
```

The returned string is the classification; a `hardening note` is a legitimate outcome and belongs in the non-findings section with the fuse state quoted.
