# Detection Signals and Blue-Team Handoff

> Sub-skill: [`web3-infrastructure-and-rpc`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- JSON-RPC requests for `eth_accounts` or `eth_sendTransaction` from an address outside the operator's range.
- A high rate of `eth_chainId` probes across many endpoints, characteristic of endpoint discovery.
- Requests to `admin_` or `personal_` namespaces on a production node.
- Front-end responses whose script tags change between fetches without a deployment.
- A dApp page loading a provider script from a domain unrelated to the project.
- Deployment key usage from a CI runner whose job is not a deployment.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
