# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cloud-incident-response`](SKILL.md) | Family: **Incident Response**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: View any user email using the Team's audit log section

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** Hello team, I decided to do some further testing, and I came across another endpoint that can be used to reveal user emails. Steps To Reproduce 1. Create a demo in your account https://hackerone.com/teams/new/sandbox 2.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: T1578.001 - Modify Cloud Compute Infrastructure: Create Snapshot

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-778`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1578.001 - Modify Cloud Compute Infrastructure: Create Snapshot > **Jargon: MITRE ATT&CK** — A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. ## Description from ATT&CK > An adversary may create a snapshot or data backu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Wrangling the M365 UAL with PowerShell and SOF-ELK (Part 1 of 3)

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-778`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Wrangling the M365 UAL with PowerShell and SOF-ELK (Part 1 of 3) When it comes to M365 audit and investigation, the “Unified Audit Log” (UAL) is your friend. It can be surly, obstinate, and wholly inadequate, but your friend nonetheless. Sadly, depending upon licensing and rete
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: PowerShell批量给Azure虚拟机磁盘创建镜像 背景 脚本编写

- **Provenance:** Source: `CYBER_CPT/pstips` | CWE: `CWE-778`
- **Context / Surface:** Source: pstips (mixed)
- **Root Cause / Analysis:** # PowerShell批量给Azure虚拟机磁盘创建镜像 # 背景 假如有一个由N台虚拟机组成的SAP系统，在上海的Azure数据中心落地，但是客户可能会想在北京数据中心搭建一套灾备系统（DR SITE）。虽然每一个数据中心都会标榜自己机房的安全性，稳定性和先进性，但是在天灾人祸不可控因素面前，为了降低业务中断时间，一套能够快速恢复的灾备系统仍旧值得拥有。 灾备系统可以重新部署，然后再同步核心数据。也可以全站复制，然后再调整核心参数。假如选择了后者，就抛出了一个问题：**如何在主站不关机的情况下，把主站的虚拟机迁移到灾备站点？** ## 为什么不选择虚
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Wrangling the M365 UAL with SOF-ELK on EC2 (Part 2 of 3)

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-778`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Wrangling the M365 UAL with SOF-ELK on EC2 (Part 2 of 3) In **[PART 1] (https://www.blackhillsinfosec.com/wrangling-the-m365-ual-with-powershell-and-sof-elk-part-1-of-3/)** of "Wrangling the M365 UAL," we talked about the value of the Unified Audit Log (UAL), some of the challen
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Wrangling the M365 UAL with SOF-ELK and CSV Data (Part 3 of 3)

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-778`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Wrangling the M365 UAL with SOF-ELK and CSV Data (Part 3 of 3) In part one of “Wrangling the M365 UAL,” we talked about acquiring, parsing, and querying UAL data using PowerShell and SOF-ELK. In part two, we discussed leveraging AWS EC2 for greater flexibility and accessibility
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Canonical LXD Arbitrary File Read via Template Injection in Snapshot Patterns

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-778`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact In LXD's instance snapshot creation functionality, the Pongo2 template engine is used in the 'snapshots.pattern' configuration for generating snapshot names. While code execution functionality has not been found in this template engine, it has file reading capabilities
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
