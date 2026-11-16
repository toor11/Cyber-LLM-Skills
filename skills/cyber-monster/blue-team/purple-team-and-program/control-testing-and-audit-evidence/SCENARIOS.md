# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`control-testing-and-audit-evidence`](SKILL.md) | Family: **Purple Team and Program**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: 证据合约系统

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-693`
- **Context / Surface:** Source: github_security_md (zh)
- **Root Cause / Analysis:** # 证据合约系统 ## 为什么需要证据合约 AI 进行源码审计时容易"看到危险函数就报漏洞"，忽略上游过滤、参数可控性、路径可达性，导致大量误报。证据合约系统强制要求每个漏洞结论附带完整数据流证明。 **核心原则**: 没有从 Source 到 Sink 的完整证据链，就不能将漏洞标记为"已确认可利用"。 ## EVID_* 命名规则 格式: 'EVID_{漏洞类型}_{证据维度}'。漏洞类型用大写缩写（SQL、CMD、XSS 等），证据维度描述该点证明的内容（EXEC_POINT=执行点、USER_PARAM=用户参数来源）。 ## 各漏洞类型证据点定
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: 2. Data Sampling

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-693`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # 2. Data Sampling {{#include ../../banners/hacktricks-training.md}} ## **Data Sampling** **Data Sampling** is a crucial process in preparing data for training large language models (LLMs) like GPT. It involves organizing text data into input and target sequences that the model u
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Lost evidence

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-693`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # [NACTF2019] — Writeup Writeup for NACTF 2019 by Nicholas. NACTF 2019 I’m going to explain my writeup for some challenges that I have done in this year NACTF 2019. # Crypto: Randomizer #2: BBOB — 625 point On this challenge, we were given a file called class-randomizer-2.c which
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Discord as a C2 and the cached evidence left behind

- **Provenance:** Source: `CYBER_CPT/pentest_partners` | CWE: `CWE-693`
- **Context / Surface:** Source: pentest_partners (en)
- **Root Cause / Analysis:** Also on this page ▾ * [Related services] (#related-services) * [Related blogs] (#related-blogs) ## **TL;DR** * Discord abused as a lightweight C2 channel for data exfiltration and beaconing * What the cache leaves behind, and how we can analyse it * Automating Cache Analysis with a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: CyberSoc / Cyber Detective CTF Write Up — Evidence Investigation

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-693`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # CyberSoc / Cyber Detective CTF Write Up — Evidence Investigation ![\\"Levent] (\\"https://miro.medium.com/v2/da:true/resize:fill:88:88/0*IiVPS9GOvy22muHQ\\") Levent Durdalı · Follow 9 min read · Jan 27, 2022 \-- Listen Share Cyber Detective CTF is an OSINT-focused CTF created by
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
