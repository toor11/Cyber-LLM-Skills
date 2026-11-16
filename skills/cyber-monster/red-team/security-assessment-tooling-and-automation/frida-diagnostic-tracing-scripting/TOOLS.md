# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`frida-diagnostic-tracing-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Frida 17.x. Static `Module.getExportByName` style APIs were removed in 17; resolve through `Process.getModuleByName(...)`.
- **Validation Gate:** `frida-ps -U` to confirm the device and `frida --version` to confirm the client matches the injected gadget.
- Frida 17.10+ accepts an options object on `attach`, `replace`, and `replaceFast` (scratch register selection, redirect emitters); the two-argument form still works.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `frida` | `frida --version` | Client version must be able to talk to the injected core on the device | Windows, Linux, macOS |
| `frida-ps` | `frida-ps -U` | Confirm the device is reachable and list attachable processes | Windows, Linux, macOS |
| `frida-trace` | `frida-trace -U -i 'verify_*' -f com.app` | Generate per-symbol hooks before writing a custom script | Windows, Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```javascript
const mod = Process.getModuleByName("libauth.so");
const fn = mod.getExportByName("verify_token");
Interceptor.attach(fn, {
  onEnter(args) { this.t0 = Date.now(); this.tok = args[0].readUtf8String(); },
  onLeave(retval) {
    send({ fn: "verify_token", n: String(this.tok).length, ret: retval.toInt32(),
           ms: Date.now() - this.t0 });
  }
});
```
