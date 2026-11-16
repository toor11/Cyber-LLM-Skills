# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`host-persistence-scheduled-and-wmi-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Rabbit

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Rabbit was all about enumeration and rabbit holes. I’ll work to quickly eliminate vectors and try to focus in on ones that seem promising. I’ll find an instance of Complain Management System, and exploit multiple SQL injections to get a dump of hashes and usernames. I’ll use them
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: WMI Event Subscription Persistence

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-269`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # WMI Event Subscription Persistence 'ruby ## # This module requires Metasploit: http://metasploit.com/download # Current source: https://github.com/rapid7/metasploit-framework ## require 'msf/core/exploit/powershell' require 'msf/core/post/windows/powershell' require 'msf/core
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Enumerating Users without net, Services without sc and Scheduled Tasks without schtasks

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Enumerating Users without net, Services without sc and Scheduled Tasks without schtasks It is possible to use MMC snap-ins to enumerate local users and local groups, services, scheduled tasks, SMB shares and sessions on a system if you have an interactive desktop session on the
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: 通过计划任务SCHTASKS远程启用Remoting 12

- **Provenance:** Source: `CYBER_CPT/pstips` | CWE: `CWE-269`
- **Context / Surface:** Source: pstips (mixed)
- **Root Cause / Analysis:** # 通过计划任务SCHTASKS远程启用Remoting @J 有分享过一片文章“[通过 Invoke-WmiMethod 启用 Remoting] (https://www.pstips.net/using-invoke-wmimethod-enable-remoting.html "通过 Invoke-WmiMethod 启用 Remoting") ”，可是我测试了好几次，每次都是运行正确，返回值为0，可以远程配置不成功。后来试了另外一个旁门左道的方法，**计划任务**。 ### 使用场景 拥有远程机器的管理权限，想从本机开启远程机器的“PowerSh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: T1053-005-win-schtasks本地计划任务

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # T1053-005-win-schtasks本地计划任务 ## 来自ATT&CK的描述 诸如at和schtasks之类的实用程序可与Windows Task Scheduler一起使用来调度程序或脚本在某日期和时间执行。只要身份认证通过可以使用RPC，并且打开了文件和打印机共享功能，就可以在远程系统上调度任务。在远程系统上调度任务通常需要远程系统管理员群组的成员执行。 攻击者可能会通过任务调度在系统启动时或在计划的基础上执行程序以实现持久性，作为横向移动的一部分进行远程执行，获得系统权限，或者在指定账号的上下文下运行进程。 ## 测试案例 安排命令和
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: WMI Persistence

- **Provenance:** Source: `CYBER_CPT/heresecurity` | CWE: `CWE-269`
- **Context / Surface:** Source: heresecurity (mixed)
- **Root Cause / Analysis:** ' https://gitee.com/RichChigga/WMI-Persistence cobalt strike ->payload generator->powershell(use x64) ' ' attack->文件下载，文件选择payload generator的脚本，local uri为随意文件 ' ' 生成后地址替换进WMI-Persistence脚本内 ' ' # powershell -exec bypass PS > Import-Module .\WMI-Persistence.ps1 PS >
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
