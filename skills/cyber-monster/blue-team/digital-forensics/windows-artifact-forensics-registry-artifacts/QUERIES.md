# Evidence Extraction Artifacts and Queries

> Sub-skill: [`windows-artifact-forensics-registry-artifacts`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `windows-artifact-forensics-registry-artifacts`. Each class names the hive and key being read, the parser invocation including transaction-log handling, and the filter that converts values into the right class of claim. `RECmd` replays `.LOG1`/`.LOG2` automatically unless `--nl` is passed.

## Class 1 — Hive inventory and dirty-hive gate

Expected hit: one row per hive with its hash, whether logs are present, and whether the base block's sequence numbers disagree. A dirty hive without logs will present stale state.

```powershell
$want = 'SYSTEM','SOFTWARE','SAM','SECURITY','DEFAULT','Amcache.hve'
$hives = Get-ChildItem C:\case\C\Windows\System32\config -Force |
         Where-Object { $want -contains $_.Name }
$hives | Select-Object Name, Length,
  @{n='Sha256';   e={ (Get-FileHash $_.FullName -Algorithm SHA256).Hash }},
  @{n='HasLog1';  e={ Test-Path "$($_.FullName).LOG1" }},
  @{n='HasLog2';  e={ Test-Path "$($_.FullName).LOG2" }} |
  Sort-Object Name | Format-Table -AutoSize
```

False-positive note: a hive can be clean (sequence numbers agree) and still have its newest value missing if it was copied mid-write. Treat "no logs present" as a staleness risk regardless of what the sequence numbers say.

## Class 2 — Control set and profile resolution

Expected hit: the numeric control set that is live, and a SID-to-profile-path map so per-user hives can be attributed.

```powershell
RECmd.exe -f C:\case\C\Windows\System32\config\SYSTEM -kn "Select" --csv C:\case\out --csvf select.csv
RECmd.exe -f C:\case\C\Windows\System32\config\SOFTWARE `
  --kn "Microsoft\Windows NT\CurrentVersion\ProfileList" --csv C:\case\out --csvf profiles.csv
Import-Csv C:\case\out\profiles.csv | Select-Object KeyPath, ValueName, ValueData | Format-Table -Wrap
```

False-positive note: `ControlSet001` is not necessarily live. Every `Services` statement must name the set resolved from `Select\Current`, or it may describe an abandoned control set that never applied.

## Class 3 — Autostart configuration

Expected hit: values under `Run`, `RunOnce`, `RunServices`, `Winlogon` `Userinit`/`Shell`, and `Services` `ImagePath`, each with a `LastWrite` timestamp.

```powershell
RECmd.exe -f C:\case\C\Windows\System32\config\SOFTWARE --bn "BatchExamples\Kroll_Batch.reb" `
  --csv C:\case\out --csvf software.csv
Import-Csv C:\case\out\software.csv |
  Where-Object { $_.KeyPath -match 'CurrentVersion\\Run|Winlogon' } |
  Select-Object KeyPath, ValueName, ValueData, LastWriteTimestamp | Format-Table -Wrap
```

False-positive note: a `Run` value proves configuration only. Many persist after the binary is deleted, and OEM and management tooling populate these keys on every host. Without a `LastWrite` inside the window and a peer-host comparison, a hit is a baseline entry.

## Class 4 — User interaction history

Expected hit: `UserAssist` run counts and last-execution times with ROT13-decoded names, plus `RunMRU`, `TypedPaths` and `RecentDocs` entries.

```powershell
RECmd.exe -f "C:\case\C\Users\alice\NTUSER.DAT" --bn "BatchExamples\Kroll_Batch.reb" `
  --csv C:\case\out --csvf ntuser.csv
Import-Csv C:\case\out\ntuser.csv |
  Where-Object { $_.KeyPath -match 'UserAssist|RunMRU|TypedPaths|RecentDocs' } |
  Select-Object KeyPath, ValueName, ValueData, LastWriteTimestamp | Format-Table -Wrap
```

False-positive note: `UserAssist` records Explorer-launched GUI programs only, and its value names are ROT13-encoded, so a raw grep for a program name will miss the entry entirely. `RunMRU` records typed text that may never have resolved to a program.

## Class 5 — Device and volume history

Expected hit: `USBSTOR` instance keys with vendor, product, serial and typed `Properties` timestamps, matched to `MountedDevices` volume mappings and per-user `MountPoints2`.

```powershell
RECmd.exe -f C:\case\C\Windows\System32\config\SYSTEM `
  --kn "ControlSet001\Enum\USBSTOR" --csv C:\case\out --csvf usbstor.csv
Import-Csv C:\case\out\usbstor.csv | Select-Object KeyPath, ValueName, ValueData, LastWriteTimestamp |
  Format-Table -Wrap
```

False-positive note: an instance key whose name has `&` as its second character is a Windows-generated identifier, not the device's own serial, so it will not match the same device on another host. Check the instance-name pattern before asserting cross-host device identity.

## Class 6 — Amcache inventory retained after deletion

Expected hit: `Root\InventoryApplicationFile` entries carrying a SHA-1 for paths that no longer exist on disk.

```powershell
RECmd.exe -f C:\case\config\Amcache.hve --kn "Root\InventoryApplicationFile" --csv C:\case\out --csvf inv.csv
Import-Csv C:\case\out\inv.csv | Where-Object { $_.KeyPath -match 'InventoryApplicationFile' } |
  Select-Object KeyPath, ValueName, LastWriteTimestamp | Select-Object -First 30
```

False-positive note: the SHA-1 in Amcache covers only a prefix of large files and will not match a full-file hash. Compare against a prefix-aware hash or accept the mismatch on files above the threshold.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the control set, profile SID and transaction-log presence beside every registry finding.
