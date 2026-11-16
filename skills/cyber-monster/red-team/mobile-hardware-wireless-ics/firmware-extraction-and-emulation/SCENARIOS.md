# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`firmware-extraction-and-emulation`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Cloudinspect

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-284`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Introductory Networking : TryHackMe Task 1: Introduction In this room, we’ll delve into various fundamental topics of networking and explore practical applications. Here’s what we’ll cover: 1. The OSI Model 2. The TCP/IP Model 3. Practical demonstrations of these models 4. Intr
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: A Deep Dive Into Samsung's TrustZone - "TAG, SSDs and Firmware Extraction"Manipulating AES Traffic

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-284`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Hardware Debugging for Reverse Engineers Part 2: JTAG, SSDs and Firmware Extraction # Background To follow up on my [last post] (https://wrongbaud.github.io/posts/stm-xbox-jtag/) about SWD and hardware debugging, I wanted to do a deep dive into JTAG from a reverse-engineering pe
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Expressway

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Expressway is a Linux box with only SSH and an IKE VPN service on UDP. I’ll use 'ike-scan' in aggressive mode to leak the VPN identity and capture a pre-shared key hash, which cracks quickly with hashcat. Connecting to the IPSEC VPN doesn’t provide any additional attack surface,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Vault

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Vault was a really neat box in that it required pivoting from a host into various VMs to get to the vault, at least the intended way. There’s an initial php upload filter bypass that gives me execution. Then a pivot with an OpenVPN config RCE. From there I’ll find SSH creds, and
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: 编写 QEMU 模拟设备

- **Provenance:** Source: `CYBER_CPT/ctf_wiki` | CWE: `CWE-284`
- **Context / Surface:** Source: ctf_wiki (mixed)
- **Root Cause / Analysis:** # 编写 QEMU 模拟设备 本节我们将介绍如何在 QEMU 中编写一个新的模拟设备。 > 注1：在开始之前你可能需要补充一些[PCI 设备的基础知识] (https://arttnba3.cn/2022/08/30/HARDWARE-0X00-PCI_DEVICE/) > > 注2：qemu 官方在 'hw/misc/edu.c' 中也提供了一个教学用的设备样例，red hat 则在 'hw/misc/pci-testdev.c' 中提供了一个测试设备，我们可以参考这两个设备来构建我们的设备 ## QEMU Object Model 在 Qemu 当中有
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: QEMU 逃逸入门

- **Provenance:** Source: `CYBER_CPT/ctf_wiki` | CWE: `CWE-284`
- **Context / Surface:** Source: ctf_wiki (mixed)
- **Root Cause / Analysis:** # QEMU 逃逸入门 QEMU 逃逸本质上和用户态的 Pwn 题没有太大区别，只不过呈现形式略有不同。题目本身通常以一个 QEMU 模拟设备的形式进行呈现，该设备通常会实现一些功能并提供用户可操纵的 MMIO/PMIO 接口。选手通常需要编写一个与这些接口进行交互的程序并传到远程主机上运行以完成利用（类似于内核 Pwn）。 下面我们通过一道例题来了解 QEMU Pwn 题目的基本做法。 ## 例题：BlizzardCTF2017 - Strng > 注：题目环境可以在 [Github] (https://github.com/rcvalle/blizza
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
