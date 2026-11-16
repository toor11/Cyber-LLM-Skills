# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`network-forensics-and-pcap-malicious-traffic-identification`](SKILL.md) | Family: **Digital Forensics**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Jarmis

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** My favorite part about Jarmis was that it is centered around this really neat technology used to fingerprint and identify TLS servers. There's an application that will scan a given server and report back the Jarm signature, and if that signature matches something potentially mali
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: You Need To Know jq

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** jq is such a nifty tool that not nealry enough people know about. If you’re working with json data, even just small bits here and there, it’s worth knowing the basics to make some simple data manipulations possible. And if you want to become a full on jq wizard, all the better. I
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: 从TLS指纹到流量阻断：基于JA3与Suricata的恶意软件检测实战

- **Provenance:** Source: `CYBER_CPT/xz_aliyun` | CWE: `CWE-345`
- **Context / Surface:** Source: xz_aliyun (zh)
- **Root Cause / Analysis:** # 从TLS指纹到流量阻断：基于JA3与Suricata的恶意软件检测实战 随着HTTPS加密通信的普及，传统基于明文特征的流量检测方法逐渐失效，恶意软件也越来越多地利用TLS协议隐藏其通信行为，给安全检测带来了新的挑战。针对这一问题，JA3指纹技术通过对TLS ClientHello消息中的关键字段进行特征提取与哈希计算，实现了在加密流量环境下对客户端行为的有效识别。
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HackBack

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-345`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # TryHackMe The Sticker shop ![\\"Some] (\\"https://miro.medium.com/v2/da:true/resize:fill:88:88/0*VLB9MAlfp8-ZGBfn\\") Some Shitty Learner · Follow 3 min read · Dec 10, 2024 Listen Share Hey, I will show case my take on stumbling to capture the flag in the new Easy mode The Stick
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Adapting to Change: JA3 Fingerprints Fade as Browsers Embrace TLS Extension Randomization

- **Provenance:** Source: `CYBER_CPT/secwiki` | CWE: `CWE-345`
- **Context / Surface:** Source: secwiki (en)
- **Root Cause / Analysis:** [![Stamus-Logo-with-R-color-small] (https://www.stamus-networks.com/hubfs/Stamus-Logo-with-R-color-small.png "Stamus-Logo-with-R-color-small")] (https://www.stamus-networks.com/?hsLang=en) * [Solutions] (https://www.stamus-networks.com/network-detection-and-response) + [Optimize you
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: 如何绕过 JA3 指纹校验？

- **Provenance:** Source: `CYBER_CPT/secwiki` | CWE: `CWE-345`
- **Context / Surface:** Source: secwiki (en)
- **Root Cause / Analysis:** 之前看过某些文章，很好地论证了 JA3 指纹不能作为设备指纹的特征。也让我对 JA3 指纹的具体的细节和在其他方面的应用产生了兴趣，这里我们站在攻击者的视角，以代码的角度记录下 JA3 的计算和生成自定义 JA3 指纹。 关于 JA3 指纹生成 JA3 的出现由 John B. Althouse、Jeff Atkinson、Josh Atkins 三个人共同在 2017 年提出（三个人的姓名首字母都为 JA，合称即为 JA3），而 JA3 指纹的生成，则要从 TLS 建立握手开始说起。TLS 在建立握手时，以客户端发起 ClientHello 开始，告诉
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
