# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ghidra-headless-and-pcode-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Patched Function Found by Call Inventory

- **Surface & Preconditions:** A vendor patch changes one function's call targets without changing its size.
- **Root Cause & Impact:** Size-based comparison misses it; the call inventory differential names the exact address.
- **Verification & Fix:** Run the P-code call inventory on both builds, diff the target sets per function entry, and report the address that gained a call.

## Case 2: Stripped Binary With Invented Names

- **Surface & Preconditions:** An analyst reports a dangerous function because the decompiler labelled it `strcpy_like`.
- **Root Cause & Impact:** The name is a heuristic from the decompiler, not a symbol from the binary.
- **Verification & Fix:** Confirm the behaviour from P-code memory operations and the call target, and label the function by what it does rather than by the guessed name.
