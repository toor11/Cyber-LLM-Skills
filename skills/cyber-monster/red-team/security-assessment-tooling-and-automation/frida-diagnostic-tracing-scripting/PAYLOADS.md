# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`frida-diagnostic-tracing-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `frida-diagnostic-tracing-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Baseline action vs hooked action

Baseline: perform the action with no script attached and record the observable outcome. Probe: the same action with the single-symbol hook. Differential: one trace line per call, present only for the action under test.

```javascript
const f = Process.getModuleByName("libauth.so").getExportByName("verify_token");
Interceptor.attach(f, { onEnter(a) { this.s = a[0].readUtf8String(); }, onLeave(r) { send({ ret: r.toInt32(), n: String(this.s).length }); } });
```

## Managed method check

Baseline: call the method through the UI. Probe: the same call with the overload hooked. Differential: exactly one record per invocation, with argument values matching the UI input.

```javascript
Java.perform(() => { const C = Java.use('com.app.Auth'); C.login.overload('java.lang.String').implementation = function (u) { send({ u }); return this.login(u); }; });
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
