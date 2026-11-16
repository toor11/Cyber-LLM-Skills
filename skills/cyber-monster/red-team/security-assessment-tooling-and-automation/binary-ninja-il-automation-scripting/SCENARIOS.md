# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`binary-ninja-il-automation-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Statically Linked Parser With an Indirect Dispatch

- **Surface & Preconditions:** A firmware image contains a parser that dispatches through a function-pointer table, and the audit must enumerate reachable handlers.
- **Root Cause & Impact:** A byte-pattern search for indirect calls returns every virtual dispatch including statically linked libc, so the inventory is unusable.
- **Verification & Fix:** Walk MLIL calls, resolve the table entries, keep only handlers reachable from the exported parse entry, and print the defining instruction for each.

## Case 2: Length Argument Sourced From a Read

- **Surface & Preconditions:** A handler passes a length read from the packet into a copy loop.
- **Root Cause & Impact:** MLIL shows the variable, but only the SSA definition chain shows that the value comes from the read rather than a constant.
- **Verification & Fix:** Print the definition chain for the length argument and confirm the origin instruction is the read, then check for a bound between the read and the call.
