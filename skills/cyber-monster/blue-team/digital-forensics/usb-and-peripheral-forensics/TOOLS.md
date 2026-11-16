# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`usb-and-peripheral-forensics`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for removable-device analysis on Windows. Confirm options with `<tool> --help`; `RECmd` replays hive transaction logs automatically unless `--nl` is supplied, which matters because late `USBSTOR` property writes may exist only in the logs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `RECmd` | `RECmd.exe -f <SYSTEM> -kn "ControlSet001\Enum\USBSTOR" --csv <out>` | Scoped device enumeration and property extraction with log replay | Windows |
| `Registry Explorer` | GUI open of SYSTEM with the `USBSTOR` bookmark | Visual verification of the typed `Properties` values and their byte layout | Windows |
| `USBDeviceForensics` | GUI, load SYSTEM then SOFTWARE then NTUSER.DAT | Correlates enumeration, mount history and per-user attribution in one view | Windows |
| `LECmd` | `LECmd.exe -d <Recent> --csv <out>` and `JLECmd.exe -d <AutomaticDestinations> --csv <out>` | LNK targets with volume serials and jump-list entries for file-access proof | Windows |
| `MFTECmd` | `MFTECmd -f '$J' -m '$MFT' --csv <out>` | Journal records for paths on the removable volume | Windows |
| `EvtxECmd` | `EvtxECmd.exe -f "Microsoft-Windows-Partition%4Diagnostic.evtx" --csv <out>` | Partition diagnostic events with device and disk identifiers, plus Sysmon 29 executable-detected records | Windows |

## Minimal Script Shape

The shape below keeps UTC registry time and local PnP-log time in separate outputs and labels each instance ID as hardware or Windows-generated. Read-only against the collected hives.

```bash
#!/usr/bin/env bash
# usb-scope.sh — replay gate, lifecycle timeline, explicit time-base separation.
set -euo pipefail
CFG="${1:?usage: $0 <config-dir> [setupapi.dev.log]}"
SETUP="${2:-}"; OUT="${3:-./derived}"; mkdir -p "$OUT"

# 0. Replay gate: late USBSTOR property writes may live only in the logs.
if [ ! -e "$CFG/SYSTEM.LOG1" ] && [ ! -e "$CFG/SYSTEM.LOG2" ]; then
  echo "STALE RISK: SYSTEM has no .LOG1/.LOG2 -> newest device values may be absent" | tee "$OUT/gaps.txt"
fi

# 1. Enumeration and lifecycle, UTC.
RECmd.exe -f "$CFG/SYSTEM" -kn "ControlSet001/Enum/USBSTOR" --csv "$OUT" --csvf usbstor.csv -q

awk -F, '
  NR>1 && $0 ~ /83da6326/ {
    split($0, f, ",");
    key = f[1]; val = f[NF-1]; data = f[NF];
    if (key ~ /0064$/)      print "FIRST_INSTALL_UTC|" key "|" data;
    else if (key ~ /0066$/) print "LAST_ARRIVAL_UTC|"  key "|" data;
    else if (key ~ /0067$/) print "LAST_REMOVAL_UTC|"  key "|" data;
  }' "$OUT/usbstor.csv" | sort -t'|' -k2 > "$OUT/usb_lifecycle_utc.txt"

# 2. Instance-ID class: '&' as second character means Windows generated it.
awk -F, '/USBSTOR.Disk/ {split($1,p,"\\\\"); print p[3]}' "$OUT/usbstor.csv" 2>/dev/null |
  sort -u | awk '{printf "%s|%s\n", $0, (substr($0,2,1)=="&" ? "GENERATED" : "HARDWARE_SERIAL")}' \
  > "$OUT/instance_ids.txt"

# 3. PnP install log kept in LOCAL time, never merged with the UTC file above.
if [ -n "$SETUP" ] && [ -f "$SETUP" ]; then
  { echo "# LOCAL TIME - convert via SYSTEM\\ControlSet001\\Control\\TimeZoneInformation before comparison"
    grep -n -A2 'USBSTOR\\\\Disk' "$SETUP" | head -40
  } > "$OUT/setupapi_local.txt"
fi

paste -sd' ' - < "$OUT/usb_lifecycle_utc.txt" | cut -c1-300
```

## Notes That Prevent Wrong Runs

- `RECmd -kn` needs the full key path from the hive root; a partial path returns nothing silently rather than erroring, which reads like an empty key.
- The `Properties\{83da6326-...}` values are typed: `0x0010` is FILETIME, `0x0012` is UTF-16LE string and `0x0007` is a 32-bit integer. Decode by type, not by position.
- `setupapi.dev.log` rotates to `setupapi.dev.*.log`. If the current file starts after the device install, check the archives and Volume Shadow Copies before reporting the install log as absent.
- A `Partmgr` `DiskId` value and a LNK `VolumeSerialNumber` are related but not identical identifiers; map through `MountedDevices` rather than comparing them directly.
