# Verification Probes and Expected Differentials

> Sub-skill: [`firmware-extraction-and-emulation`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Layer inventory

```text
# Signatures and offsets, then a per-megabyte entropy profile.
binwalk firmware.bin
binwalk -E --save entropy.png firmware.bin
python - <<'FIRMWAREEXTRAC97EB_CLASS1'
import math, collections  # firmware-extraction-and-emulation: class 1 layer inventory
data = open("firmware.bin","rb").read()
for i in range(0, len(data), 1 << 20):
    chunk = data[i:i + (1 << 20)]
    c = collections.Counter(chunk)
    ent = -sum((n/len(chunk)) * math.log2(n/len(chunk)) for n in c.values())
    print(f"{i:#010x} entropy={ent:.2f}")
FIRMWAREEXTRAC97EB_CLASS1
```

Expected differential: a stepped entropy profile means containers; a flat 7.9 profile means compression or encryption with no visible signature, which changes the next step.

## Class 2 — Filesystem extraction

```text
binwalk -e --run-as=root firmware.bin >/dev/null 2>&1
unsquashfs -l squashfs-root/*.squashfs | head -20
unsquashfs -d rootfs squashfs-root/*.squashfs >/dev/null
rg -n --no-heading "PRIVATE KEY|password|passwd=" rootfs/etc/ rootfs/usr/ 2>/dev/null | head -10
rg -n --no-heading "telnetd|dropbear|sshd|httpd" rootfs/etc/init.d/ rootfs/etc/rc* 2>/dev/null
```

Expected differential: a readable rootfs with a private key or a remote shell started by init is the finding, and each line carries the file path. A rootfs with locked accounts and no remote shell is the control.

## Class 3 — Emulation harness

```text
# Boot the extracted kernel and rootfs under qemu with a recorded console.
qemu-system-arm -M versatilepb -kernel rootfs/boot/zImage -dtb rootfs/boot/versatile-pb.dtb \
  -drive file=rootfs.img,format=raw,if=scsi -append "root=/dev/sda console=ttyAMA0" \
  -nographic -net nic -net user,hostfwd=tcp::8080-:80
```

Expected differential: a console that reaches the init sequence shows which services start and with what configuration; a kernel panic on an unsupported machine means the emulation needs a different board model, which is a tooling limit rather than a finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
