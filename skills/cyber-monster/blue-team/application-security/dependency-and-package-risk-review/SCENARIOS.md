# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`dependency-and-package-risk-review`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Pinning Cheat Sheet

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-1357`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Pinning Cheat Sheet ## Introduction The Pinning Cheat Sheet is a technical guide to implementing certificate and public key pinning as discussed by Jeffrey Walton at the Virginia chapter's presentation [Securing Wireless Channels in the Mobile Space] (https://wiki.owasp.org/imag
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Android Frida 动态分析与 SSL Pinning 绕过

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-1357`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # Android Frida 动态分析与 SSL Pinning 绕过 ## Frida 环境配置 ### frida-server 部署 'bash # 查看设备架构 adb shell getprop ro.product.cpu.abi # arm64-v8a → frida-server-xx.x.x-android-arm64 # 下载对应版本 # https://github.com/frida/frida/releases # 推送到设备 adb push frida-server-xx.x.x-android-arm64 /data
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: CoreDNS: DNS Cache Pinning via etcd Lease ID Confusion

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-1357`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # CoreDNS: DNS Cache Pinning via etcd Lease ID Confusion - **OSV ID**: GHSA-93mf-426m-g6x9 - **CVE**: CVE-2025-58063 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H - **Published**: 2025-09-09T19:19:33Z - **Modified**: 2026-02-04T03:10:19.897140Z - **Affected Packages**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: PikaTwoo

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-1357`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![PikaTwoo] (/img/pikatwoo-cover.png) PikaTwoo is an absolute monster of an insane box. I’ll start by abusing a vulnerability in OpenStack’s KeyStone to leak a username. With that username, I’ll find an Android application file in the OpenStack Swift object storage. The applicatio
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Android Anti-Instrumentation & SSL Pinning Bypass (Frida/Objection)

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-1357`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Android Anti-Instrumentation & SSL Pinning Bypass (Frida/Objection) {{#include ../../banners/hacktricks-training.md}} This page provides a practical workflow to regain dynamic analysis against Android apps that detect/root‑block instrumentation or enforce TLS pinning. It focuse
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Certificate Pinning Bypass

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-1357`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **Certificate Pinning Bypass** refers to techniques used to circumvent certificate pinning protections in mobile apps or clients, allowing man-in-the-middle interception of HTTPS traffic for security testing or malicious purposes. ### What is Certificate Pinning? Certificate pinn
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
