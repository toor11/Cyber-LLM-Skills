# Digital Forensics

> Tree: `blue-team/digital-forensics` | **27 sub-skills** | Root router: [`../../SKILL.md`](../../SKILL.md)

**Weak-Model Rule:** Pick the **1 best matching** sub-skill below (`flagship` or `core` first unless a variant profile matches exactly), read its `SKILL.md`, and answer directly using its *Strict Output Contract*.

| Sub-skill | Tier | Focus & When to Use |
|---|---|---|
| [`memory-forensics`](memory-forensics/SKILL.md) | **flagship** | Analyses volatile memory: acquisition, profile selection, process and injection detection, network artifacts and credential recovery with Volatil |
| [`windows-artifact-forensics`](windows-artifact-forensics/SKILL.md) | **flagship** | Analyses Windows artefacts: registry hives, event logs, prefetch, shimcache and amcache, USN journal, LNK files and jump lists to reconstruct exe |
| [`anti-forensics-detection`](anti-forensics-detection/SKILL.md) | **core** | Detects anti-forensic activity: log manipulation, timestomping, artefact deletion and secure wiping indicators |
| [`browser-and-application-forensics`](browser-and-application-forensics/SKILL.md) | **core** | Analyses browser and application artefacts: history, downloads, cache, extensions, saved credentials and web app storage |
| [`cloud-forensics-and-acquisition`](cloud-forensics-and-acquisition/SKILL.md) | **core** | Acquires evidence from cloud environments: snapshot and log preservation, provider tooling constraints and multi-tenant evidence boundaries |
| [`disk-forensics-and-artifacts`](disk-forensics-and-artifacts/SKILL.md) | **core** | Collects and analyses disk evidence: imaging with verification, filesystem parsing, deleted file recovery and artefact interpretation |
| [`linux-forensics`](linux-forensics/SKILL.md) | **core** | Analyses Linux hosts: log review, bash history, persistence locations, package and file integrity, and container-adjacent artefacts |
| [`log-and-timeline-analysis`](log-and-timeline-analysis/SKILL.md) | **core** | Builds and analyses timelines across multiple sources: normalization, super-timelining and correlating events to establish sequence |
| [`macos-forensics`](macos-forensics/SKILL.md) | **core** | Analyses macOS hosts: unified logging, launch services persistence, quarantine events, FSEvents and TCC database artefacts |
| [`mobile-device-forensics`](mobile-device-forensics/SKILL.md) | **core** | Acquires and analyses mobile device evidence: logical versus full filesystem acquisition, app data parsing and communication artefacts |
| [`network-forensics-and-pcap`](network-forensics-and-pcap/SKILL.md) | **core** | Analyses network traffic: pcap triage, protocol reconstruction, extracting transferred files and identifying malicious flows |
| [`registry-and-file-system-forensics`](registry-and-file-system-forensics/SKILL.md) | **core** | Analyses registry and filesystem structures: hive parsing, key timestamps, MFT and $LogFile analysis, and timeline correlation |
| [`saas-workspace-and-entra-unified-audit-forensics`](saas-workspace-and-entra-unified-audit-forensics/SKILL.md) | **core** | Acquires and analyses Microsoft Purview Unified Audit Logs (UAL), Entra SignIn/Audit logs, and Google Workspace Admin/Token logs: reconstructing |
| [`container-and-kubernetes-forensics`](container-and-kubernetes-forensics/SKILL.md) | **leaf** | Investigates container and Kubernetes incidents: container filesystem capture, image layer analysis, audit log review and node-level evidence |
| [`database-forensics`](database-forensics/SKILL.md) | **leaf** | Investigates database evidence: transaction log analysis, deleted row recovery, access auditing and integrity verification |
| [`email-forensics`](email-forensics/SKILL.md) | **leaf** | Analyses email evidence: header analysis, attachment examination, mailbox artefacts and delivery path reconstruction |
| [`file-carving-and-recovery`](file-carving-and-recovery/SKILL.md) | **leaf** | Recovers deleted and fragmented files: carving signatures, container parsing and handling compressed or encrypted remnants |
| [`forensic-imaging-and-tooling`](forensic-imaging-and-tooling/SKILL.md) | **leaf** | Performs defensible acquisition: write blocking, imaging formats, verification hashing and tool validation |
| [`memory-forensics-network-and-credential-artifacts`](memory-forensics-network-and-credential-artifacts/SKILL.md) | **leaf** | Memory network and credential artefacts |
| [`memory-forensics-process-and-injection-analysis`](memory-forensics-process-and-injection-analysis/SKILL.md) | **leaf** | Process and injection analysis in memory |
| [`network-forensics-and-pcap-malicious-traffic-identification`](network-forensics-and-pcap-malicious-traffic-identification/SKILL.md) | **leaf** | Malicious traffic identification |
| [`network-forensics-and-pcap-protocol-reconstruction`](network-forensics-and-pcap-protocol-reconstruction/SKILL.md) | **leaf** | Protocol reconstruction from capture |
| [`usb-and-peripheral-forensics`](usb-and-peripheral-forensics/SKILL.md) | **leaf** | Analyses USB and peripheral artefacts: device connection history, removable storage usage and data transfer evidence |
| [`windows-artifact-forensics-event-log-artifacts`](windows-artifact-forensics-event-log-artifacts/SKILL.md) | **leaf** | Windows event log artefacts |
| [`windows-artifact-forensics-execution-artifacts`](windows-artifact-forensics-execution-artifacts/SKILL.md) | **leaf** | Windows execution artefacts |
| [`windows-artifact-forensics-file-system-artifacts`](windows-artifact-forensics-file-system-artifacts/SKILL.md) | **leaf** | Windows filesystem artefacts |
| [`windows-artifact-forensics-registry-artifacts`](windows-artifact-forensics-registry-artifacts/SKILL.md) | **leaf** | Windows registry artefacts |
