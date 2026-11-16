# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Error on unsupported architectures in raw-cpuid

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-693`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** native_cpuid::cpuid_count() exposes the unsafe __cpuid_count() intrinsic from core::arch::x86 or core::arch::x86_64 as a safe function, and uses it internally, without checking the safety requirement: * The CPU the program is currently running on supports the function being calle
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: In CPUID CPU-Z before 1.43, there is an arbitrary memory write that results directly in elevation of

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-693`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # In CPUID CPU-Z before 1.43, there is an arbitrary memory write that results directly in elevation of privileges, because any program running on the local machine (while CPU-Z is running) can issue an - **CVE**: CVE-2017-15303 - **Exploit Type**: AwesomePoc - **Exploit ID**: Awe
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: An issue was discovered in the raw-cpuid crate before 9.0.0 for Rust. It allows __cpuid_count() call

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-693`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An issue was discovered in the raw-cpuid crate before 9.0.0 for Rust. It allows __cpuid_count() calls even if the processor does not support the CPUID instruction, which is unsound and causes a determ - **CVE**: CVE-2021-26307 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: In CPUID CPU-Z through 1.81, there are improper access rights to a kernel-mode driver (e.g., cpuz143

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-693`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # In CPUID CPU-Z through 1.81, there are improper access rights to a kernel-mode driver (e.g., cpuz143_x64.sys for version 1.43) that can result in information disclosure or elevation of privileges, bec - **CVE**: CVE-2017-15302 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Deserialization of Untrusted Data in rust-cpuid

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-693`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** An issue was discovered in the raw-cpuid crate before 9.1.1 for Rust. If the serialize feature is used (which is not the the default), a Deserialize operation may lack sufficient validation, leading to memory corruption or a panic.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
