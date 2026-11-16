# Evidence Extraction Artifacts and Queries

> Sub-skill: [`usb-and-peripheral-forensics`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `usb-and-peripheral-forensics`. Each class names the store being read, the parser, and the comparison that turns device history into a claim. Registry FILETIMEs are UTC; `setupapi.dev.log` is local time and is kept separate on purpose.

## Class 1 — Enumeration and device class

Expected hit: `Enum\USB` instance keys with VID/PID and the device's `iSerialNumber`, showing which classes were ever attached.

```powershell
RECmd.exe -f C:\case\config\SYSTEM -kn "ControlSet001\Enum\USB" --csv C:\case\out --csvf enumusb.csv
Import-Csv C:\case\out\enumusb.csv | Select-Object KeyPath, ValueName, ValueData |
  Where-Object { $_.KeyPath -match 'VID_' } | Select-Object -First 40
```

False-positive note: an empty `Enum\USB` on a host that visibly uses USB peripherals usually means the SYSTEM hive was collected without its transaction logs, not that no device was ever attached. Confirm log presence before drawing a conclusion.

## Class 2 — Mass-storage lifecycle timestamps

Expected hit: `USBSTOR` instances with the typed `Properties` values `0064`, `0065`, `0066` and `0067` decoded to UTC FILETIMEs.

```powershell
RECmd.exe -f C:\case\config\SYSTEM -kn "ControlSet001\Enum\USBSTOR" --csv C:\case\out --csvf usbstor.csv
Import-Csv C:\case\out\usbstor.csv | Where-Object { $_.KeyPath -match '83da6326|Partmgr' } |
  Select-Object KeyPath, ValueName, ValueData | Format-Table -Wrap
```

False-positive note: `0064`/`0065` record first installation and `0066`/`0067` the most recent arrival and removal — they are not a full connection history. A device plugged in twenty times shows one first-install and one last-arrival.

## Class 3 — UASP devices under the SCSI enumerator

Expected hit: a storage device present under `Enum\SCSI` with the same serial as an `Enum\USB` entry but no `USBSTOR` instance.

```powershell
RECmd.exe -f C:\case\config\SYSTEM -kn "ControlSet001\Enum\SCSI" --csv C:\case\out --csvf scsi.csv
Import-Csv C:\case\out\scsi.csv | Where-Object { $_.KeyPath -match 'Disk&Ven_USB' } |
  Select-Object KeyPath, ValueName, ValueData | Select-Object -First 30
```

False-positive note: a storage device with no `USBSTOR` entry is not evidence of concealment — UASP devices are enumerated by the SCSI driver and never appear in `USBSTOR`. Check `Enum\SCSI` before concluding the device was not attached.

## Class 4 — Volume mapping and per-user attribution

Expected hit: `MountedDevices` letters and volume GUIDs, matched to a `MountPoints2` volume key inside one user's `NTUSER.DAT`.

```powershell
RECmd.exe -f C:\case\config\SYSTEM -kn "MountedDevices" --csv C:\case\out --csvf mounted.csv
RECmd.exe -f C:\case\Users\alice\NTUSER.DAT `
  -kn "Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" --csv C:\case\out --csvf mp_alice.csv
Import-Csv C:\case\out\mp_alice.csv | Where-Object { $_.KeyPath -match 'Volume\{' } | Select-Object KeyPath
```

False-positive note: `mountvol /r` and OS upgrades can remove `MountedDevices` entries, and `MountPoints2` persists after the volume is gone. Absence of a mapping does not prove the volume was never mounted; its presence attributes the mount to that profile.

## Class 5 — First-contact timing from the PnP log

Expected hit: a `setupapi.dev.log` section for the instance ID, with the local timestamp and the SYSTEM hive's time zone both visible.

```bash
grep -n -A3 "USBSTOR\\\\Disk" /case/Windows/INF/setupapi.dev.log | head -30
grep -n "TimeZoneKeyName\|Bias" /case/derived/system_tz.txt
```

False-positive note: the log has no zone marker and is written in local time. Comparing it directly with a UTC FILETIME produces a whole-hour offset that reads like two separate install events; convert first and report both values.

## Class 6 — File access from the volume

Expected hit: LNK or jump-list entries whose volume serial matches the device, or journal records for a path on that volume.

```powershell
LECmd.exe -d "C:\case\Users\alice\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\case\out --csvf lnk.csv
Import-Csv C:\case\out\lnk.csv |
  Select-Object SourceFile, TargetIDAbsolutePath, VolumeSerialNumber, DriveType | Format-Table -Wrap
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=29} -MaxEvents 200 |
  Select-Object TimeCreated, @{n='Msg';e={$_.Message -replace "`r`n",' '}} | Select-Object -First 20
```

False-positive note: a LNK volume serial identifies a volume, not a physical device — cloned drives share serials and reformatted volumes keep their assigned serial. Corroborate against `USBSTOR` before naming hardware.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the hive replay state, the time-zone conversion applied, and the instance-ID class beside every device finding.
