# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`linux-lateral-movement`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: SSH Agent Forwarding Exploitation

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** SSH Agent Forwarding Exploitation {{#include ../../banners/hacktricks-training.md}} Summary What can you do if you discover inside the '/etc/ssh_config' or inside '$HOME/.ssh/config' configuration this: ForwardAgent yes If you are root inside the machine you can probably **access any ssh connection...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: HTB: CrossFit

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** CrossFit is all about chaining attacks together to get the target to do my bidding. It starts with a cross-site scripting (XSS) attack against a website. The site detects the attack, and forwards my user agent to the admins to investigation. An XSS payload in the user-agent will
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Ghoul

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Ghoul was a long box, that involved pioviting between multiple docker containers exploiting things and collecting information to move to the next step. With a level of pivoting not seen in HackTheBox since Reddish, I’ll need to pay careful attention to various passwords and other
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Exploiting NFS shares to gain root access

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-269`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Exploiting NFS shares to gain root access Recently, while performing a network-level penetration testing activity for one of the clients, I came across a vulnerability that was used to compromise almost all the systems in scope. In this article, we will learn how to exploit a w
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: 挂载 docker.sock 导致容器逃逸

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # 挂载 docker.sock 导致容器逃逸 ## 漏洞描述 Docker Socket 是 Docker 守护进程监听的 Unix 域套接字，用来与守护进程通信——查询信息或下发命令。如果在攻击者可控的容器内挂载了该套接字文件（/var/run/docker.sock），可通过 Docker Socket 与 Docker 守护进程通信，发送命令创建并运行一个新的容器，将宿主机的根目录挂载到新创建的容器内部，完成简单逃逸。 ## 环境搭建 基础环境准备（Docker + Minikube + Kubernetes），可参考 [Kubernetes +
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Linux Lateral Movement

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** Note: When using a domain account, we need to include the domain name, for example: administrator@inlanefreight.htb ## Pass the Hash with Impacket (Linux) ### Pass the Hash with Impacket PsExec 'bash impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D06
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
