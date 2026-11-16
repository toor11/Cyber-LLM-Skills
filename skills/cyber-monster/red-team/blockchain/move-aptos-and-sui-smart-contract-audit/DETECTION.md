# Detection Signals and Blue-Team Handoff

> Sub-skill: [`move-aptos-and-sui-smart-contract-audit`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Publishing a module whose upgrade policy permits code change to a production address.
- Calls to a mint entry function from an address that is not the module or a designated admin.
- Resource creation outside the owning module, visible as a type with an unexpected creator.
- Aborts with the module's capability error code, indicating an attempted forgery.
- Transactions supplying an authority object as a parameter rather than a signer.
- Upgrade events on a module that was published as immutable.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
