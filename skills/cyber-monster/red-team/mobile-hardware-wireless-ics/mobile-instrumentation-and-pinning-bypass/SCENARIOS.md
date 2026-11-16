# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`mobile-instrumentation-and-pinning-bypass`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Android Anti-Instrumentation & SSL Pinning Bypass (Frida/Objection)

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Android Anti-Instrumentation & SSL Pinning Bypass (Frida/Objection) {{#include ../../banners/hacktricks-training.md}} This page provides a practical workflow to regain dynamic analysis against Android apps that detect/root‑block instrumentation or enforce TLS pinning.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Android Anti-Instrumentation & SSL Pinning Bypass (Frida/Objection)

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-295`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Android Anti-Instrumentation & SSL Pinning Bypass (Frida/Objection) {{#include ../../banners/hacktricks-training.md}} This page provides a practical workflow to regain dynamic analysis against Android apps that detect/root‑block instrumentation or enforce TLS pinning. It focuse
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Break frida-objc-bridge

- **Provenance:** Source: `CYBER_CPT/tttang` | CWE: `CWE-295`
- **Context / Surface:** Source: tttang (mixed)
- **Root Cause / Analysis:** # My-CMSMS / Aug 25, 2022 ## Background > Webapps and concats * Author: Pankaj Verma * Released on: Aug 25, 2020 * Difficulty: Intermediate * Overall difficulty for me: Easy * Initial foothold: Easy * Privilege Escalation: Very easy ## Service Enumeration As usual, scan the machi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Instrumenting Windows APIs with Frida

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-295`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Instrumenting Windows APIs with Frida [Frida] (https://frida.re) is dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers. ## Spawning New Process with Frida We can ask frida to spawn a new process for us to instrument: 'bash frida c:\wind
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: iOS Frida/Objection 动态 Hook 与认证绕过

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-295`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # iOS Frida/Objection 动态 Hook 与认证绕过 ## Frida 环境配置 ### 越狱设备 'bash # Cydia 添加 Frida 源 # https://build.frida.re # 或手动安装 # 从 GitHub Releases 下载 frida-server-xx.x.x-ios-arm64.deb dpkg -i frida-server.deb # frida-server 自动以 root 启动 # PC 端验证 frida-ps -Uai ' ### 非越狱设备 (Frida Gadget)
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Fpicker

- **Provenance:** Source: `CYBER_CPT/h4cker` | CWE: `CWE-295`
- **Context / Surface:** Source: h4cker (en)
- **Root Cause / Analysis:** # fpicker fpicker is a Frida-based fuzzing suite that offers a variety of fuzzing modes for in-process fuzzing, such as an AFL++ mode or a passive tracing mode. It should run on all platforms that are supported by Frida. Some background information and the thoughts and ideas behi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Secure Notes

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-295`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Reverse Engineering Series — 1 file: link: https://github.com/d0minikkkk/reversinghero-contents/blob/master/1/x1 Tools: * file * ltrace * strings * ghex * ida64 * Ghidra # Binary Analysis file ltrace strings From the above analysis, we can find out that it uses printf, fdopen,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
