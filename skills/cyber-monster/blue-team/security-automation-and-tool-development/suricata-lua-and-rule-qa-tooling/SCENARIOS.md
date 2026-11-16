# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`suricata-lua-and-rule-qa-tooling`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative IDS rule-QA failures, each with the artifact that proves the diagnosis.

## Case 1: Rule silently dropped by the engine

- **Surface & Preconditions:** a rule set is deployed with a `requires:` keyword naming an engine feature not present in the build.
- **Root cause & impact:** Suricata 8 treats unknown requirements as unmet and refuses to load the rule. The file linter sees valid syntax and the SOC sees "no alerts" rather than "no rule".
- **Verification & fix:** gate on `suricata -T` with the production `suricata.yaml`; correlate the rule count in the load output with the count in the file.

## Case 2: fast_pattern edit changes the alert count

- **Surface & Preconditions:** a reviewer moves `fast_pattern` to a different content string to improve throughput.
- **Root cause & impact:** the chosen content also constrained which buffer was inspected, so the rule's semantics changed. Throughput improves and coverage drops.
- **Verification & fix:** treat any `fast_pattern` move as a detection change; run the malicious/benign PCAP pair before and after and compare alert counts by `sid`.

## Case 3: Lua rule never alerts and logs no error

- **Surface & Preconditions:** a script accumulates a long string inside `match()` while iterating a transaction.
- **Root cause & impact:** the Suricata 8 sandbox enforces an instruction limit, so the script is terminated rather than raising a catchable Lua error; nothing appears in the rule's error path.
- **Verification & fix:** bound every loop, avoid building unbounded strings, and reduce work per call. Add the `suricata-verify` case so a regression fails the build.

## Case 4: Stats assertions break after upgrade

- **Surface & Preconditions:** a dashboard parses `stats.whitelist` from `eve.json`.
- **Root cause & impact:** Suricata 8 renamed `stats.whitelist` to `stats.score`, so the consumer reports missing stats for a healthy engine and the team chases a nonexistent performance problem.
- **Verification & fix:** update the consumer to `stats.score`, and assert on `event_type: stats` in a `suricata-verify` case so schema drift is caught at build time.
