# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`rsa-attacks-padding-oracle`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Padding Oracle Attack

- **Provenance:** Source: `CYBER_CPT/ctf_wiki` | CWE: `CWE-326`
- **Context / Surface:** Source: ctf_wiki (mixed)
- **Root Cause / Analysis:** # Padding Oracle Attack ## 介绍 Padding Oracle Attack 攻击一般需要满足以下几个条件 - 加密算法 - 采用 PKCS5 Padding 的加密算法。 当然，非对称加密中 OAEP 的填充方式也有可能会受到影响。 - 分组模式为 CBC 模式。 - 攻击者能力 - 攻击者可以拦截上述加密算法加密的消息。 - 攻击者可以和 padding oracle（即服务器） 进行交互：客户端向服务器端发送密文，服务器端会以某种返回信息告知客户端 padding 是否正常。 Padding Oracle Attack 攻
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Web 2 Doc 1

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (mixed)
- **Root Cause / Analysis:** # Web 2 Doc 1 ## Challenge Description We needed an easy way to turn websites into PDF documents, so we implemented a simple flask app for that. Luckily, there are easy librarieres to do the hard work of print ing a website into a PDF... There's one particular endpoint we wanted
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Secret Server Revenge

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-326`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** This challenge naturally follows from Secret Server, of which you can find a writeup [here] (http://toh.necst.it/hitconquals2017/crypto/Secret_Server/). We are given [another] (http://toh.necst.it/writeups_files/secretserverrevenge/secretserver.py) python script, which pretty m
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Authlib Vulnerable to JWE RSA1_5 Bleichenbacher Padding Oracle

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-326`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## 1. Executive Summary A cryptographic padding oracle vulnerability was identified in the Authlib Python library concerning the implementation of the JSON Web Encryption (JWE) 'RSA1_5' key management algorithm. Authlib registers 'RSA1_5' in its default algorithm registry without
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: [网络安全] 二十六 Sql 注入之揭秘 Oracle 数据库注入漏洞和致命问题（Cream 老师）

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-326`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** 前文介绍了虚拟机 VMware+Kali 安装入门及 Sqlmap 基本用法。这篇文章将跟着 Cream 老师兼好友学习，结合自己的经验详细介绍 Oracle 数据库注入漏洞和致命问题，包括各种类型的注入知识。注入漏洞是安全威胁中比较常见的漏洞，Oracle 也是用得最广的数据库，希望这篇文章对您有帮助。 **一. Oracle 基础介绍** 1. 数据库介绍 2. Oracle 安装配 3. 常见注入类型 **二. Oracle 数据库元数据获取** **三. 联合注入实践** **四. 报错注入实践** **五. 布尔盲注实践** 1. 普通猜解 2
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: CTF Reverse - Runtime Patching and Oracle Techniques

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-326`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # CTF Reverse - Runtime Patching and Oracle Techniques Malware unpacking, multi-stage shellcode, timing/signal side channels, and CTF-specific oracle attacks that rely on runtime state rather than static pattern matching. For static reversing patterns (custom VMs, anti-debug, sel
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
