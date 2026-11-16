# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`express-and-fastify-security`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `npm` | `npm ls body-parser qs --all` and `npm audit --omit=dev --json` | Resolved versions and advisory matches | Cross-platform |
| `semgrep` | `semgrep scan --config p/javascript --config p/nodejs --error` | Shell, prototype, and operator-injection patterns | Cross-platform |
| `autocannon` | `autocannon -m POST -H 'content-type: application/json' -b body.json http://localhost:3000/login` | Replay the operator probe at low volume | Cross-platform |
| `curl` | `curl -sS --data-binary @payload.json -H 'content-type: application/json' -H 'content-encoding: gzip' http://localhost:3000/login` | Reproduce the compressed-body crash path on a staging instance | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```javascript
// Schema-first route: the probe shapes must fail validation, not reach the driver.
import Fastify from "fastify";

const app = Fastify({ bodyLimit: 64 * 1024 });

const loginSchema = {
  body: {
    type: "object",
    additionalProperties: false,
    required: ["email", "password"],
    properties: {
      email: { type: "string", format: "email", maxLength: 254 },
      password: { type: "string", minLength: 12, maxLength: 256 },
    },
  },
};

app.post("/login", { schema: loginSchema }, async (req) => {
  const { email, password } = req.body;          // both are strings by construction
  return auth.verify(email, password);
});

await app.listen({ port: 3000 });
export { app };
```

## Verification

- A body of `{"password": {"$ne": null}}` returns 400 from the schema, not a query result.
- A body with `__proto__` returns 400 because `additionalProperties` is false.
- A gzip body with trailing bytes is rejected by the 64 kB limit before decompression work begins.
