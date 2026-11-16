# Detection Signals and Blue-Team Handoff

> Sub-skill: [`smart-contract-audit-testing-and-invariants`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Forge or Anvil processes against a production fork endpoint from a developer host.
- Corpus or failure artefacts (`cache/inv-corpus`, `.failures`) committed to a repository.
- Invariant tests running in CI against a fork URL that points at a production RPC.
- Test suites whose runtime grows without bound, indicating unbounded handler actions.
- A test added with `vm.prank` for an address that is also an on-chain actor, which changes real state on a fork.
- Fork tests without a block number, which produce non-reproducible results across runs.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md) | Query authoring, triage, and hardening |
