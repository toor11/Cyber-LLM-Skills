# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ssti-sandbox-escape`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: H1514 Simple phishing using auto-created modal with weak URL-pattern check in incontext_app_link

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, This is unrelated to the Twine-template issue reported earlier as this would still be an issue if the template escape would be fixed. Background The 'incontext_app_link' is checked server-side if it's a correct 'shopifycloud.com'-URL.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Drink from my Flask#1

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-1336`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Drink from my Flask#1 ## Background A friend of yours got into an argument with a flask developer. He tried handling it himself, but he somehow got his nose broken in the process... Can you put your hacker skills to good use and help him out? You should probably be able to acce
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: MachineAccountQuota

- **Provenance:** Source: `CYBER_CPT/hacker_recipes` | CWE: `CWE-1336`
- **Context / Surface:** Source: hacker_recipes (en)
- **Root Cause / Analysis:** # MachineAccountQuota ## Theory > MachineAccountQuota (MAQ) is a domain level attribute that by default permits unprivileged users to attach up to 10 computers to an Active Directory (AD) domain ([source] (https://blog.netspi.com/machineaccountquota-is-useful-sometimes/)) ## Pract
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Fickling vulnerable to detection bypass due to "builtins" blindness

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-1336`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # Fickling's assessment Fickling started emitting AST nodes for builtins imports in order to match them during analysis (https://github.com/trailofbits/fickling/commit/9f309ab834797f280cb5143a2f6f987579fa7cdf). # Original report ### Summary Fickling works by Pickle bytecode --> A
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Vyper vulnerable to memory corruption in certain builtins utilizing 'msize'

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-1336`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact In certain conditions, the memory used by the builtins 'raw_call', 'create_from_blueprint' and 'create_copy_of' can be corrupted. - For 'raw_call', the argument buffer of the call can be corrupted, leading to incorrect 'calldata' in the sub-context. - For 'create_from_
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Security groups

- **Provenance:** Source: `CYBER_CPT/hacker_recipes` | CWE: `CWE-1336`
- **Context / Surface:** Source: hacker_recipes (en)
- **Root Cause / Analysis:** # Security groups ## Theory > In the Windows Server operating system, there are several built-in accounts and security groups that are preconfigured with the appropriate rights and permissions to perform specific tasks. ([Microsoft] (https://docs.microsoft.com/en-us/previous-versi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: RODC

- **Provenance:** Source: `CYBER_CPT/hacker_recipes` | CWE: `CWE-1336`
- **Context / Surface:** Source: hacker_recipes (en)
- **Root Cause / Analysis:** # RODC ## Theory > The read-only Domain Controller (RODC) is a solution that Microsoft introduced for physical locations that don’t have adequate security to host a Domain Controller but still require directory services for resources in those locations. A branch office is the cla
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
