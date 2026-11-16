# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-lateral-movement-smb-and-remote-execution`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: PsExec/Winexec/ScExec/SMBExec

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # PsExec/Winexec/ScExec/SMBExec {{#include ../../banners/hacktricks-training.md}} ## How do they work These techniques abuse the Windows Service Control Manager (SCM) remotely over SMB/RPC to execute commands on a target host. The common flow is: 1. Authenticate to the target and
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: 内网渗透（十五） Psexec 工具使用浅析 (Admin$)

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** Psexec psexec 是 windows 下非常好的一款远程命令行工具。psexec 的使用不需要对方主机开机 3389 端口，只需要对方开启 admin$ 共享 (该共享默认开启)。但是，假如目标主机开启了防火墙，psexec 也是不能使用的，会提示找不到网络路径。由于 psexec 是 windows 提供的工具，所以杀毒软件会将其添加到白名单中。 psexec 的基本原理是：通过管道在远程目标机器上创建一个 psexec 服务，并在本地磁盘中生成一个名为 "PSEXESVC" 的二进制文件。然后，通过 psexec 服务运行命令，运行结束后删
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: AtExec / SchtasksExec

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # AtExec / SchtasksExec ## How Does it works At allows to schedule tasks in hosts where you know username/(password/Hash). So, you can use it to execute commands in other hosts and get the output. ' At \\victim 11:00:00PM shutdown -r ' Using schtasks you need first to create
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Ladon 内网横向移动 Wmiexec Psexec Atexec Psexec Webshell

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** ### 前言 在内网渗透中，横向移动用的最多的就是远程执行命令了，网上有很多相关工具，系统也自带相关命令。但不是体积大就是命令繁琐，如 schtasks 命令等，执行需先创建任务、执行任务、删除任务等，命令长，输错会浪费很多时间，即使复制粘贴也很麻烦。体积大的如 Impacket 中的 psexec/atexec/smbexec/wmiexec 等，若是使用 PY2.7 编译低版本最小也 5M 左右，最大可能 37.5M，无论是内存加载或是传到目标都很麻烦，如果后渗透工具垃圾，区区这几 M 还未必能传上去，传上去得浪费很多时间。传一个就 5M，传 4 个
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Impacket Smbexec

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** ### Source https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py ### Get semi interactive powershell 'bash impacket-smbexec /:@ ' ### Using hash 'bash impacket-smbexec -hashes : /@ ' ### Op
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Impacket Atexec Creds

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** --- description: / Impacket's atexec.py uses the Task Scheduler service on the remote Windows host to execute the given command. It will create a windows task with a random name, trigger the task, and then delete it. The following command executes 'whoami' on the remote Windows h
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
