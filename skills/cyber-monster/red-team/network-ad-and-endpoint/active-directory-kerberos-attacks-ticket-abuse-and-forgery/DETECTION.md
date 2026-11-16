# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4624 logon type 9 with `Authentication Package: Negotiate` on a host where the account has no interactive history.
- Windows Security 4768 with `PreAuthType 2` and no corresponding 4648 or interactive logon on the same host within the window.
- Windows Security 4769 for a service the account has never accessed, correlated with a 4624 on the service host.
- Sysmon event 1 for `Rubeus` or `klist` invoked by a non-administrative parent process.
- Linux auditd `execve` of `kinit` with a keytab outside the sanctioned automation path, or a `KRB5CCNAME` file created in a temporary directory.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) | Query authoring, triage logic, and hardening verification |
