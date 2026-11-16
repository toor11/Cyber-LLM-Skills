# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cloud-forensics-and-acquisition`](SKILL.md) | Family: **Digital Forensics**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: T1578.001 - Modify Cloud Compute Infrastructure: Create Snapshot

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-345`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1578.001 - Modify Cloud Compute Infrastructure: Create Snapshot > **Jargon: MITRE ATT&CK** — A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. ## Description from ATT&CK > An adversary may create a snapshot or data backu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB Sherlock: Nubilum-1

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Nubilum-1] (/icons/sherlock-nubilum-1.png) Nublium-1 is all about cloud forensics, specifically a compromised AWS account that leads to multiple EC2 VM instances, including one acting as a PoshC2 server. I’ll work through the CloudTrail logs in a Splunk instance (run via Docker
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: PowerShell批量给Azure虚拟机磁盘创建镜像 背景 脚本编写

- **Provenance:** Source: `CYBER_CPT/pstips` | CWE: `CWE-345`
- **Context / Surface:** Source: pstips (mixed)
- **Root Cause / Analysis:** # PowerShell批量给Azure虚拟机磁盘创建镜像 # 背景 假如有一个由N台虚拟机组成的SAP系统，在上海的Azure数据中心落地，但是客户可能会想在北京数据中心搭建一套灾备系统（DR SITE）。虽然每一个数据中心都会标榜自己机房的安全性，稳定性和先进性，但是在天灾人祸不可控因素面前，为了降低业务中断时间，一套能够快速恢复的灾备系统仍旧值得拥有。 灾备系统可以重新部署，然后再同步核心数据。也可以全站复制，然后再调整核心参数。假如选择了后者，就抛出了一个问题：**如何在主站不关机的情况下，把主站的虚拟机迁移到灾备站点？** ## 为什么不选择虚
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Canonical LXD Arbitrary File Read via Template Injection in Snapshot Patterns

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-345`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact In LXD's instance snapshot creation functionality, the Pongo2 template engine is used in the 'snapshots.pattern' configuration for generating snapshot names. While code execution functionality has not been found in this template engine, it has file reading capabilities
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: AWS - EBS Snapshot Dump

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-345`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # AWS - EBS Snapshot Dump ## Checking a snapshot locally 'bash # Install dependencies pip install 'dsnap[cli]' brew install vagrant brew install virtualbox # Get snapshot from image mkdir snap_wordir; cd snap_workdir dsnap init ## Download a snapshot of the volume of that insta
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Grafana: Users outside an organization can delete a snapshot with its key

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-345`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary The ***DELETE /api/snapshots/{key}*** endpoint allows any Grafana user to delete snapshots if the user is NOT in the organization of the snapshot ### Details An attacker (a user without organization affiliation or with a "no basic role" in an organization other than t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
