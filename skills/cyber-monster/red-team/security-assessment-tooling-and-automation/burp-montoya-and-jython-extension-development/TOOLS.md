# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`burp-montoya-and-jython-extension-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Montoya API 2026.7; `HttpHandler`, `ScanCheck`, `RequestExecutionEngine` with `RequestEngineOptions`.
- **Validation Gate:** `gradle build` then load the jar in Extender and confirm the expected registration lines in the extension output.
- Jython extensions can only reach the subset of the API the bridge exposes; when a class is missing, switch to Java rather than mocking it.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `gradle` | `gradle build` | Build the extension jar with its Montoya dependency | Cross-platform |
| `burp Montoya jar` | `gradle dependencies --configuration runtimeClasspath` | Confirm the exact Montoya artifact version in use | Cross-platform |
| `unzip` | `unzip -l build/libs/extension.jar` | Verify the jar contains the extension class and no stray test classes | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```java
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.ResponseReceivedAction;

public class AuditExt implements BurpExtension {
    public void initialize(MontoyaApi api) {
        api.extension().setName("audit-observer");
        api.http().registerHttpHandler(new HttpHandler() {
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived r) {
                api.logging().logToOutput(r.initiatedBy().httpService().toString());
                return ResponseReceivedAction.continueWith(r);
            }
        });
    }
}
```
