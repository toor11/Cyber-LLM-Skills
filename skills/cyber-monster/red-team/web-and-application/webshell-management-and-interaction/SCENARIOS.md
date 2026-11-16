# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`webshell-management-and-interaction`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Antsword 高级用法

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-434`
- **Context / Surface:** Source: github_security_md (zh)
- **Root Cause / Analysis:** antsword 代码结构 ------------- ### 总体来看分为两部分 1. loader，包含了 electron 环境相关的一些代码，一般不需要关心 2. source，包含 antsword 界面和逻辑代码 ### source 下的几个重要目录和文件 * antData 里面包含缓存数据，编码器解码器，插件源码，所有的 shell 信息 * modules 包含了 antsword 功能逻辑的底层支持代码，包括发送请求，更新等 * source 这里包含了和不同类型脚本相关的代码，包括内置编码器，内置的对应脚本功能代码 编码器解码器开
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Hospital

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-434`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Hospital] (/img/hospital-cover.png) Hospital is a Windows box with an Ubuntu VM running the company webserver. I’ll bypass upload filters and disable functions to get a PHP webshell in the VM and execution. I’ll escalate using kernel exploits, showing both CVE-2023-35001 and Gam
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: 【As Exploits】你不能错过的 Antsword 插件

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-434`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** 前言 -- As-Exploits，中国蚁剑后渗透模块。**本文将介绍 v1.2 更新内容，并介绍该插件目前已有的功能。** 目前插件的定位是蚁剑的一个**微内核拓展模块**，可以迅速做到 Payload 的工程化，不用过多时间浪费在插件的结构上。目前的 As-Exlpoits 各部分之间基本做到了解耦，新增一个 payload 只需要两步：1. 填写 payload，2. 画一个表单。其余发包，回显处理等事情框架会自动帮你实现。想要自定义的话只需要继承父类然后重写对应方法即可。 其中 Payload 部分很多借鉴了冰蝎跟哥斯拉的实现，向其开发者们表示感
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: ILIAS before 5.2.4 has XSS via the cmd parameter to the displayHeader function in setup/classes/clas

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-434`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # ILIAS before 5.2.4 has XSS via the cmd parameter to the displayHeader function in setup/classes/class.ilSetupGUI.php in the Setup component. - **CVE**: CVE-2018-5688 - **Exploit Type**: InTheWild - **Exploit ID**: InTheWild-b35fab1eac90d99440cb6383f0087a27 - **URL**: https://ww
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: D-Link DI-8200 16.07.26A1 is vulnerable to remote command execution in the msp_info_htm function via

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-434`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # D-Link DI-8200 16.07.26A1 is vulnerable to remote command execution in the msp_info_htm function via the flag parameter and cmd parameter. - **CVE**: CVE-2024-51151 - **Exploit Type**: InTheWild - **Exploit ID**: InTheWild-66fa07db99e86f73b66553b3b728afde - **URL**: https://git
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Weevely

- **Provenance:** Source: `CYBER_CPT/kali_tools_zh` | CWE: `CWE-434`
- **Context / Surface:** Source: kali_tools_zh (en)
- **Root Cause / Analysis:** ## WeevelyеҢ…иЈ…иҜҙжҳҺ WeevelyжҳҜдёҖдёӘйҡҗеҪўзҡ„PHPзҪ‘йЎөеӨ–еЈіпјҢжЁЎжӢҹзҡ„telnetзұ»дјјзҡ„иҝһжҺҘгҖӮе®ғжҳҜWebеә”з”ЁзЁӢеәҸејҖеҸ‘еҗҺзҡ„дёҖдёӘйҮҚиҰҒе·Ҙе…·пјҢе№¶дё”еҸҜд»Ҙз”ЁдҪңйҡҗеҪўеҗҺй—ЁжҲ–дҪңдёәзҪ‘з»ңзҡ„еӨ–еЈіпјҢд»Ҙз®ЎзҗҶеҗҲжі•зҡ„зҪ‘з»ңиҙҰжҲ·пјҢз”ҡиҮіе…Қиҙ№жүҳз®Ўзҡ„гҖӮ иө„ж–ҷжқҘжәҗ
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
