# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`dns-and-beacon-analytics-dga-and-tunneling`](SKILL.md) | Family: **Detection and Monitoring**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: TryHackMe / DNS Manipulation Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe / DNS Manipulation Walkthrough Manipulating DNS queries to our advantage Link- https://tryhackme.com/room/dnsmanipulation If you were on Windows, what command could you use to query a txt record for ‘youtube.com’? nslookup -type=txt youtube.com If you were on Linux, what command could you use to query a...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: Entropy

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-778`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # SecNotes HackTheBox Write-up # Recon Let's scan our target. 'bash nmap -sV -sC -oA scan/all_ports $IP -Pn ' We have 3 open ports on the target let's check the SMB. ## SMB Enumeration Let's see if we can access SMB without a password. 'bash smbclient -N -L //$IP/ ' I don
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: The Mechanics of Compromising Low Entropy RSA Keys

- **Provenance:** Source: `CYBER_CPT/infocon` | CWE: `CWE-778`
- **Context / Surface:** Source: infocon (en)
- **Root Cause / Analysis:** # The mechanics of compromising low entropy RSA keys Nominally: Recovering private keys from a subset of vulnerable RSA certificates Functionally: Calculating shared factors across large batches of integers "...using our scalable GCD algorithm for shared factors..." "...batch GCD
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Entropy Solver

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-778`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # TryHackMe / Brooklyn Nine Nine Çözümü Bağlantımı sağladıktan sonra makineyi çalıştırdım ve ip adresini öğrendim. Çözümde kullandığım adres 10.10.85.157 oldu. nmap sorgusu attığımda 22 ftp portunun açık olduğunu gördüm. Ftp ye girmek için anonymous : pass denedim ve giriş başarı
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: The devices are vulnerable to session hijacking due to insufficient entropy in its session ID gener

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-778`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** The devices are vulnerable to session hijacking due to insufficient entropy in its session ID generation algorithm. The session IDs are predictable, with only 32,768 possible values per user, which allows attackers to pre-generate valid session IDs, leading to unauthorized access
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Insecure entropy in Argo CD's PKCE/Oauth2/OIDC params

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-778`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Insecure entropy in Argo CD's PKCE/Oauth2/OIDC params - **OSV ID**: GHSA-2m7h-86qq-fp4v - **CVE**: CVE-2022-31034 - **CVSS**: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H - **Published**: 2022-06-21T20:03:23Z - **Modified**: 2024-08-21T15:26:57.452148Z - **Affected Packages**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Want entropy? Don’t use a floating ADC input

- **Provenance:** Source: `CYBER_CPT/pentest_partners` | CWE: `CWE-778`
- **Context / Surface:** Source: pentest_partners (en)
- **Root Cause / Analysis:** Following on from our post discussing the [risks of inadequate entropy in IoT devices] (https://www.pentestpartners.com/security-blog/iot-encryption-the-challenge-of-missing-entropy/), I wanted to look at one particular method used to gather entropy – using a floating ADC (analog
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
