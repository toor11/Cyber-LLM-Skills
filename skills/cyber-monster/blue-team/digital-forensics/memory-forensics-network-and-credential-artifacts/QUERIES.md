# Evidence Extraction Artifacts and Queries

> Sub-skill: [`memory-forensics-network-and-credential-artifacts`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction recipes owned by `memory-forensics-network-and-credential-artifacts`. Each class names where the artefact lives in the image, the parser invocation that recovers it, and the timeline filter that turns rows into a finding. Every class states the expected hit and the false-positive note that must be cleared first. Plugin names are Volatility 3 2.26.2+ (`windows.*` for these five plugins; the malware family moved to `windows.malware.*`).

## Class 1 — Image gate: symbol and layer resolution

Expected hit: a banner line with a kernel base address, a build string and a detected layer name. Anything else means every later class returns a partial or empty population that reads like a quiet host.

```bash
vol -f host.dmp windows.info | tee info.txt
grep -Ei "Kernel Base|MajorMinor|Is64Bit|DTB" info.txt
```

False-positive note: `windows.info` succeeding does not mean every plugin resolved. `netscan` builds its own symbol table from pool-tag constraints and can fail independently; a zero-row `netscan` beside a healthy `windows.info` is a constraint mismatch, not an absence of sockets.

## Class 2 — Kernel pool socket objects

Expected hit: endpoint rows with local address, local port, protocol, state, owning PID and create time. The owning PID is the only column linking a socket to a process, and it is empty for objects whose EPROCESS is gone.

```bash
vol -f host.dmp windows.netscan > netscan.txt
awk 'NR>2 && $3=="LISTENING" {print $1, $5, $6}' netscan.txt | sort -u
vol -f host.dmp windows.netstat > netstat.txt
comm -23 <(awk 'NR>2 {print $5":"$6}' netscan.txt | sort -u) <(awk 'NR>2 {print $5":"$6}' netstat.txt | sort -u)
```

False-positive note: a socket appearing in `netscan` but not `netstat` is expected for exited processes and is the normal teardown state of every terminated updater. The differential is only interesting when the same remote tuple also appears in an independent flow record.

## Class 3 — Process-attributed endpoint ownership

Expected hit: an `ImageFileName` and full path for the PID that owned the endpoint, resolving to a directory outside `System32` and `Program Files`.

```bash
PID=$(awk 'NR>2 && $3=="LISTENING" {print $1; exit}' netscan.txt)
vol -f host.dmp windows.pslist --pid "$PID"
vol -f host.dmp windows.dlllist --pid "$PID"
vol -f host.dmp windows.cmdline --pid "$PID"
```

False-positive note: `windows.pslist` does not list processes whose EPROCESS was unlinked before capture. An empty `pslist` for a PID that `netscan` reports is not a contradiction — it is precisely the unlinked-process case, and `windows.psscan` is the source that can still recover it.

## Class 4 — Local account verifiers from the resident SAM image

Expected hit: one row per local account with RID, LM verifier and NT verifier. Empty-LM and empty-NT constants mark accounts with blank or disabled passwords and are not evidence of extraction.

```bash
vol -f host.dmp windows.hashdump > cred_hashdump.txt
awk 'NR>2 {print $2, $1}' cred_hashdump.txt | sort -n | head -20
```

False-positive note: every local account has a verifier in the SAM image whether or not anything read it. Treat the presence of a hash as a statement about the host's account population, and only treat an exact byte match against an on-disk verifier as proof the same value was recovered twice.

## Class 5 — Cached domain credentials and LSA secrets

Expected hit: `cachedump` returns DCC2 rows only on a domain-joined host that has logged on interactively; `lsadump` returns service-account secrets, autologon `DefaultPassword`, and the `DPAPI_SYSTEM` key on essentially every host.

```bash
vol -f host.dmp windows.cachedump > cred_cachedump.txt
vol -f host.dmp windows.lsadump > cred_lsadump.txt
grep -Ei "DefaultPassword|DPAPI|_SC_" cred_lsadump.txt | cut -c1-100
```

False-positive note: a workgroup-joined host returns zero `cachedump` rows by design. Reporting that zero as "no domain logons occurred" is a category error, because the host never had a domain cache to populate. A populated `DefaultPassword` is a configuration exposure requiring rotation, not proof of adversary collection.

## Class 6 — Timeline correlation of socket and credential artefacts

Expected hit: endpoint create times and process create times forming an ordered sequence inside the incident window, with the credential plugins showing which accounts were resident at capture time.

```bash
vol -f host.dmp windows.netscan | awk 'NR>2 && $8!="N/A" {print $8, $1, $5":"$6, $3}' | sort > net_timeline.txt
vol -f host.dmp windows.pslist | awk 'NR>2 {print $9, $1, $3}' | sort > proc_timeline.txt
head -5 net_timeline.txt proc_timeline.txt
```

False-positive note: `netscan` create times come from the kernel object and survive pool reuse in some cases, so a create time older than the process create time indicates object reuse rather than a long-lived implant. Reconcile both before quoting either as the start of activity.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the Volatility version and symbol pack used beside every exported row set; a plugin rename or symbol gap changes what an empty result means.
