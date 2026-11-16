# Network, Active Directory and Endpoint

> Tree: `red-team/network-ad-and-endpoint` | **95 sub-skills** | Root router: [`../../SKILL.md`](../../SKILL.md)

**Weak-Model Rule:** Pick the **1 best matching** sub-skill below (`flagship` or `core` first unless a variant profile matches exactly), read its `SKILL.md`, and answer directly using its *Strict Output Contract*.

| Sub-skill | Tier | Focus & When to Use |
|---|---|---|
| [`active-directory-kerberos-attacks`](active-directory-kerberos-attacks/SKILL.md) | **flagship** | Exploits Kerberos in Active Directory: Kerberoasting, AS-REP roasting, delegation abuse, ticket forgery with golden and silver tickets, and S4U a |
| [`linux-privilege-escalation`](linux-privilege-escalation/SKILL.md) | **flagship** | Escalates from a low-privileged Linux session to root: SUID binaries, sudo misconfiguration, cron jobs, capabilities, NFS root squash, writable p |
| [`windows-privilege-escalation`](windows-privilege-escalation/SKILL.md) | **flagship** | Escalates from a low-privileged Windows session to administrator or SYSTEM: service and permission misconfigurations, token abuse, unquoted paths |
| [`active-directory-acl-and-delegation-abuse`](active-directory-acl-and-delegation-abuse/SKILL.md) | **core** | Exploits misconfigured AD permissions and delegation: GenericAll, WriteDACL, ForceChangePassword, AddMember, unconstrained and constrained delega |
| [`active-directory-certificate-services`](active-directory-certificate-services/SKILL.md) | **core** | Exploits AD CS misconfigurations: ESC1 through ESC8, certificate template abuse, CA permission flaws, NTLM relay to HTTP enrollment, and certific |
| [`active-directory-enumeration`](active-directory-enumeration/SKILL.md) | **core** | Enumerates Active Directory without credentials or with a low-privileged account: domain and forest discovery, user and group enumeration, SPN di |
| [`active-directory-persistence`](active-directory-persistence/SKILL.md) | **core** | Establishes durable AD access: golden and diamond tickets, SID history, AdminSDHolder, skeleton keys, DCShadow, and certificate-based persistence |
| [`antivirus-evasion-and-obfuscation`](antivirus-evasion-and-obfuscation/SKILL.md) | **core** | Evades signature and heuristic detection: loader design, encryption and encoding, packers, polymorphic stubs, string obfuscation and sandbox chec |
| [`byovd-and-driver-abuse`](byovd-and-driver-abuse/SKILL.md) | **core** | Exploits vulnerable signed drivers to disable protections and escalate to kernel: BYOVD identification, vulnerable driver blocklist gaps, and pra |
| [`c2-implant-and-beaconing`](c2-implant-and-beaconing/SKILL.md) | **core** | Operates implants and beacons: listener selection, sleep and jitter tuning, egress channel choice, task management and interactive shell upgrade |
| [`c2-infrastructure-and-redirectors`](c2-infrastructure-and-redirectors/SKILL.md) | **core** | Designs and operates command and control infrastructure: domain and certificate selection, redirectors, CDN fronting, categorization, and resilie |
| [`credential-dumping`](credential-dumping/SKILL.md) | **core** | Extracts credentials from a compromised host or domain: LSASS and SAM dumps, DPAPI secrets, cached credentials, browser stores, and NTDS.dit extr |
| [`defense-evasion-and-log-tampering`](defense-evasion-and-log-tampering/SKILL.md) | **core** | Reduces forensic visibility: log clearing, event log manipulation, timestomping, indicator removal, security tool tampering and audit policy abus |
| [`edr-evasion-and-amsi-bypass`](edr-evasion-and-amsi-bypass/SKILL.md) | **core** | Evades endpoint detection and response and AMSI: understanding sensor telemetry, AMSI bypass mechanics, script and memory evasion, ETW patching, |
| [`entra-id-and-hybrid-identity`](entra-id-and-hybrid-identity/SKILL.md) | **core** | Attacks Microsoft Entra ID and hybrid identity: token theft, consent phishing, service principal abuse, password spray against cloud identities, |
| [`host-persistence`](host-persistence/SKILL.md) | **core** | Establishes persistence on compromised hosts: registry run keys, services, scheduled tasks, WMI subscriptions, startup folders, shell profiles an |
| [`initial-access-via-phishing`](initial-access-via-phishing/SKILL.md) | **core** | Achieves initial access through phishing: pretext design, payload and link delivery, device code and MFA fatigue flows, macro and container abuse |
| [`lolbins-and-signed-binary-abuse`](lolbins-and-signed-binary-abuse/SKILL.md) | **core** | Executes and disguises activity using living-off-the-land binaries, signed Microsoft utilities, installers and drivers: LOLBAS, GTFOBins, LOLDriv |
| [`macos-security-bypass`](macos-security-bypass/SKILL.md) | **core** | Escalates and bypasses security controls on macOS: TCC prompt abuse, Gatekeeper and notarization bypass, launchd persistence, keychain access, an |
| [`network-protocol-attacks`](network-protocol-attacks/SKILL.md) | **core** | Exploits network protocol weaknesses: LLMNR and NBT-NS poisoning, WPAD abuse, ARP spoofing, DHCP and IPv6 rogue services, and VLAN hopping |
| [`network-recon-and-port-scanning`](network-recon-and-port-scanning/SKILL.md) | **core** | Maps a network: host discovery, port and service scanning, OS fingerprinting, and scan timing under detection pressure |
| [`ntlm-relay-and-coercion`](ntlm-relay-and-coercion/SKILL.md) | **core** | Relays and coerces NTLM authentication: SMB and HTTP relay, LDAP relay for RBCD, authentication coercion primitives, and signing and channel-bind |
| [`password-cracking-and-wordlists`](password-cracking-and-wordlists/SKILL.md) | **core** | Recovers passwords from hashes and captures: hash identification, rule and mask strategy, wordlist sourcing, and GPU versus CPU tradeoffs plus ne |
| [`pivoting-and-tunneling`](pivoting-and-tunneling/SKILL.md) | **core** | Routes traffic into otherwise unreachable networks: SOCKS proxies, port forwarding, SSH and chisel tunnels, DNS and ICMP tunnelling, and protocol |
| [`process-injection-techniques`](process-injection-techniques/SKILL.md) | **core** | Injects code into other processes: classic remote threads, APC injection, process hollowing, module stomping, thread hijacking and callback-based |
| [`service-enumeration`](service-enumeration/SKILL.md) | **core** | Enumerates discovered services for users, shares, versions and configuration: SMB, LDAP, NFS, RDP, WinRM, MSSQL, FTP, SSH, SNMP and web managemen |
| [`windows-lateral-movement`](windows-lateral-movement/SKILL.md) | **core** | Moves laterally between Windows hosts: SMB and admin shares, WinRM, WMI, scheduled tasks, service creation, PsExec-class techniques and RDP |
| [`active-directory-acl-genericall-writedacl`](active-directory-acl-genericall-writedacl/SKILL.md) | **leaf** | GenericAll and WriteDACL abuse |
| [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](active-directory-acl-and-delegation-abuse-group-and-ou-abuse/SKILL.md) | **leaf** | Group and OU permission abuse |
| [`active-directory-acl-targeted-kerberoast-shadow-credentials`](active-directory-acl-targeted-kerberoast-shadow-credentials/SKILL.md) | **leaf** | Shadow credentials and targeted abuse |
| [`active-directory-certificate-services-esc1-through-esc4`](active-directory-certificate-services-esc1-through-esc4/SKILL.md) | **leaf** | ADCS ESC1 to ESC4 template abuse |
| [`active-directory-certificate-services-esc5-through-esc8`](active-directory-certificate-services-esc5-through-esc8/SKILL.md) | **leaf** | ADCS ESC5 to ESC8 CA and relay abuse |
| [`active-directory-enumeration-authenticated-enumeration`](active-directory-enumeration-authenticated-enumeration/SKILL.md) | **leaf** | Authenticated AD enumeration and path mapping |
| [`active-directory-enumeration-gpo-and-administrative-discovery`](active-directory-enumeration-gpo-and-administrative-discovery/SKILL.md) | **leaf** | GPO and administrative control discovery |
| [`active-directory-enumeration-unauthenticated-enumeration`](active-directory-enumeration-unauthenticated-enumeration/SKILL.md) | **leaf** | Unauthenticated AD enumeration |
| [`active-directory-kerberos-attacks-asrep-roasting`](active-directory-kerberos-attacks-asrep-roasting/SKILL.md) | **leaf** | AS-REP roasting |
| [`active-directory-kerberos-attacks-delegation`](active-directory-kerberos-attacks-delegation/SKILL.md) | **leaf** | Kerberos delegation abuse |
| [`active-directory-kerberos-attacks-golden-and-silver-tickets`](active-directory-kerberos-attacks-golden-and-silver-tickets/SKILL.md) | **leaf** | Golden and silver ticket forgery |
| [`active-directory-kerberos-attacks-kerberoasting`](active-directory-kerberos-attacks-kerberoasting/SKILL.md) | **leaf** | Kerberoasting |
| [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md) | **leaf** | Kerberos ticket manipulation |
| [`active-directory-trust-and-forest-abuse`](active-directory-trust-and-forest-abuse/SKILL.md) | **leaf** | Abuses AD trusts between domains and forests: SID filtering gaps, trust key extraction, cross-domain group membership, and forest-level escalatio |
| [`credential-dumping-dpapi-and-secret-stores`](credential-dumping-dpapi-and-secret-stores/SKILL.md) | **leaf** | DPAPI and application secret stores |
| [`credential-dumping-lsass-and-memory`](credential-dumping-lsass-and-memory/SKILL.md) | **leaf** | LSASS and process memory credential extraction |
| [`credential-dumping-sam-and-ntds`](credential-dumping-sam-and-ntds/SKILL.md) | **leaf** | SAM, SECURITY and NTDS.dit extraction |
| [`defense-evasion-and-log-tampering-indicator-removal`](defense-evasion-and-log-tampering-indicator-removal/SKILL.md) | **leaf** | Indicator and artefact removal |
| [`defense-evasion-and-log-tampering-log-and-audit-evasion`](defense-evasion-and-log-tampering-log-and-audit-evasion/SKILL.md) | **leaf** | Log and audit trail evasion |
| [`edr-evasion-and-amsi-bypass-amsi-bypass`](edr-evasion-and-amsi-bypass-amsi-bypass/SKILL.md) | **leaf** | AMSI bypass |
| [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) | **leaf** | ETW and telemetry evasion |
| [`edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection`](edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection/SKILL.md) | **leaf** | Sandbox and analysis environment detection |
| [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) | **leaf** | Userland unhooking and direct syscalls |
| [`firewall-and-segmentation-testing`](firewall-and-segmentation-testing/SKILL.md) | **leaf** | Tests network segmentation and firewall rules: egress restrictions, ACL gaps, cross-VLAN reachability, and protocol tunnelling past filters |
| [`host-persistence-linux-and-macos-persistence`](host-persistence-linux-and-macos-persistence/SKILL.md) | **leaf** | Linux and macOS persistence |
| [`host-persistence-registry-and-service-persistence`](host-persistence-registry-and-service-persistence/SKILL.md) | **leaf** | Registry and service persistence |
| [`host-persistence-scheduled-and-wmi-persistence`](host-persistence-scheduled-and-wmi-persistence/SKILL.md) | **leaf** | Scheduled task and WMI persistence |
| [`initial-access-via-edge-devices`](initial-access-via-edge-devices/SKILL.md) | **leaf** | Achieves initial access through internet-facing edge devices: VPN, firewall, mail gateway and web appliance n-days, exposed management interfaces |
| [`linux-lateral-movement`](linux-lateral-movement/SKILL.md) | **leaf** | Moves laterally on Linux: SSH key reuse, agent forwarding abuse, shared NFS and home directories, Ansible and config management credentials, and |
| [`linux-privilege-escalation-cron-and-systemd`](linux-privilege-escalation-cron-and-systemd/SKILL.md) | **leaf** | Cron and systemd abuse |
| [`linux-privilege-escalation-kernel-and-container-escapes`](linux-privilege-escalation-kernel-and-container-escapes/SKILL.md) | **leaf** | Linux kernel and container boundary escalation |
| [`linux-privilege-escalation-nfs-and-share-abuse`](linux-privilege-escalation-nfs-and-share-abuse/SKILL.md) | **leaf** | NFS and share permission abuse |
| [`linux-privilege-escalation-sudo-abuse`](linux-privilege-escalation-sudo-abuse/SKILL.md) | **leaf** | Linux sudo misconfiguration abuse |
| [`linux-privilege-escalation-suid-and-capabilities`](linux-privilege-escalation-suid-and-capabilities/SKILL.md) | **leaf** | SUID binaries and Linux capabilities |
| [`lolbins-and-signed-binary-abuse-download-and-staging`](lolbins-and-signed-binary-abuse-download-and-staging/SKILL.md) | **leaf** | LOLBin download and staging |
| [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](lolbins-and-signed-binary-abuse-driver-blocklist-gaps/SKILL.md) | **leaf** | LOLDrivers and driver blocklist gaps |
| [`lolbins-and-signed-binary-abuse-execution-proxies`](lolbins-and-signed-binary-abuse-execution-proxies/SKILL.md) | **leaf** | LOLBin execution proxies |
| [`macos-security-bypass-gatekeeper-and-notarization`](macos-security-bypass-gatekeeper-and-notarization/SKILL.md) | **leaf** | Gatekeeper and notarization bypass |
| [`macos-security-bypass-tcc-and-privacy-bypass`](macos-security-bypass-tcc-and-privacy-bypass/SKILL.md) | **leaf** | macOS TCC and privacy control bypass |
| [`network-protocol-attacks-capture-and-intercept`](network-protocol-attacks-capture-and-intercept/SKILL.md) | **leaf** | Traffic capture and interception |
| [`network-protocol-attacks-ipv6-and-dhcp-abuse`](network-protocol-attacks-ipv6-and-dhcp-abuse/SKILL.md) | **leaf** | IPv6 and DHCP abuse |
| [`network-protocol-attacks-layer-two-attacks`](network-protocol-attacks-layer-two-attacks/SKILL.md) | **leaf** | Layer two network attacks |
| [`network-protocol-attacks-name-resolution-poisoning`](network-protocol-attacks-name-resolution-poisoning/SKILL.md) | **leaf** | Name resolution poisoning |
| [`network-recon-and-port-scanning-external-perimeter-scanning`](network-recon-and-port-scanning-external-perimeter-scanning/SKILL.md) | **leaf** | External perimeter scanning |
| [`network-recon-and-port-scanning-internal-network-mapping`](network-recon-and-port-scanning-internal-network-mapping/SKILL.md) | **leaf** | Internal network mapping |
| [`ntlm-relay-and-coercion-coercion-primitives`](ntlm-relay-and-coercion-coercion-primitives/SKILL.md) | **leaf** | NTLM authentication coercion primitives |
| [`ntlm-relay-and-coercion-relay-targets`](ntlm-relay-and-coercion-relay-targets/SKILL.md) | **leaf** | NTLM relay target selection |
| [`pivoting-and-tunneling-dns-and-icmp-tunnels`](pivoting-and-tunneling-dns-and-icmp-tunnels/SKILL.md) | **leaf** | DNS and ICMP tunnelling |
| [`pivoting-and-tunneling-socks-and-port-forwarding`](pivoting-and-tunneling-socks-and-port-forwarding/SKILL.md) | **leaf** | SOCKS proxying and port forwarding |
| [`process-injection-techniques-classic-and-apc-injection`](process-injection-techniques-classic-and-apc-injection/SKILL.md) | **leaf** | Classic thread and APC injection |
| [`process-injection-techniques-hollowing-and-stomping`](process-injection-techniques-hollowing-and-stomping/SKILL.md) | **leaf** | Process hollowing and module stomping |
| [`process-injection-techniques-injection-via-callbacks`](process-injection-techniques-injection-via-callbacks/SKILL.md) | **leaf** | Injection through callback mechanisms |
| [`reverse-shells-and-payload-delivery`](reverse-shells-and-payload-delivery/SKILL.md) | **leaf** | Delivers and stabilizes reverse shells: listener selection, payload generation for each interpreter, tty upgrade, egress-restricted alternatives, |
| [`service-enumeration-database-and-remote-access`](service-enumeration-database-and-remote-access/SKILL.md) | **leaf** | Database and remote access service enumeration |
| [`service-enumeration-ldap-and-directory`](service-enumeration-ldap-and-directory/SKILL.md) | **leaf** | LDAP and directory service enumeration |
| [`service-enumeration-smb-and-netbios`](service-enumeration-smb-and-netbios/SKILL.md) | **leaf** | SMB and NetBIOS enumeration |
| [`service-enumeration-snmp-and-infrastructure`](service-enumeration-snmp-and-infrastructure/SKILL.md) | **leaf** | SNMP and infrastructure service enumeration |
| [`windows-internals-and-api-abuse`](windows-internals-and-api-abuse/SKILL.md) | **leaf** | Uses Windows internals deliberately: token manipulation, handle duplication, privilege enabling, PPL and protected process targeting, and native |
| [`windows-lateral-movement-pass-the-hash-and-ticket`](windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) | **leaf** | Pass-the-hash and pass-the-ticket movement |
| [`windows-lateral-movement-rdp-and-session-abuse`](windows-lateral-movement-rdp-and-session-abuse/SKILL.md) | **leaf** | RDP and session hijacking |
| [`windows-lateral-movement-smb-and-remote-execution`](windows-lateral-movement-smb-and-remote-execution/SKILL.md) | **leaf** | SMB and remote execution lateral movement |
| [`windows-lateral-movement-winrm-and-wmi`](windows-lateral-movement-winrm-and-wmi/SKILL.md) | **leaf** | WinRM and WMI lateral movement |
| [`windows-privilege-escalation-credential-and-config-exposure`](windows-privilege-escalation-credential-and-config-exposure/SKILL.md) | **leaf** | Windows credential and configuration exposure |
| [`windows-privilege-escalation-kernel-and-driver-escalation`](windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) | **leaf** | Windows kernel and driver local escalation |
| [`windows-privilege-escalation-service-and-path-flaws`](windows-privilege-escalation-service-and-path-flaws/SKILL.md) | **leaf** | Windows service and path misconfiguration |
| [`windows-privilege-escalation-token-and-privilege-abuse`](windows-privilege-escalation-token-and-privilege-abuse/SKILL.md) | **leaf** | Windows token and privilege abuse |
| [`windows-privilege-escalation-uac-bypass`](windows-privilege-escalation-uac-bypass/SKILL.md) | **leaf** | Windows UAC bypass |
| [`windows-service-and-scheduled-task-abuse`](windows-service-and-scheduled-task-abuse/SKILL.md) | **leaf** | Abuses Windows services and scheduled tasks for execution and escalation: service permissions, binary path tampering, task creation as SYSTEM and |
