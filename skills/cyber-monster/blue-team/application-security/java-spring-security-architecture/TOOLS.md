# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`java-spring-security-architecture`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `mvn` | `mvn -q dependency:tree -Dincludes=org.springframework.boot` | Resolved Boot version for advisory matching | Java |
| `gradle` | `gradle dependencies --configuration runtimeClasspath` | Same for Gradle builds | Java |
| `semgrep` | `semgrep scan --config p/java --config p/spring --error` | Chain ordering and deserialisation patterns | Cross-platform |
| `curl` | `curl -sS -o /dev/null -w '%{http_code}\n' http://staging:8080/actuator/env` | Actuator exposure probe | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Evidence: chain ordering, actuator exposure, and Boot version.
set -euo pipefail
grep -rn --include='*.java' -E 'requestMatchers|permitAll|securityMatcher' src/main/java | sed 's/^/  /'
grep -rn --include='*.properties' --include='*.yml' -E 'management\.endpoints\.web\.exposure|management\.server\.port' src/main/resources || true
mvn -q help:evaluate -Dexpression=spring-boot.version -DforceStdout 2>/dev/null || \
  grep -m1 'springBootVersion' build.gradle || true
printf 'actuator probe: '; curl -sS -o /dev/null -w '%{http_code}\n' "${BASE:-http://localhost:8080}/actuator/env"
```

## Verification

- The grep output shows matcher order as written, which is the artefact the review argument rests on.
- The actuator probe returns 401/404; a 200 with a body means the endpoint is open.
- The printed Boot version resolves to a release you can check against the 2026 advisory list.
