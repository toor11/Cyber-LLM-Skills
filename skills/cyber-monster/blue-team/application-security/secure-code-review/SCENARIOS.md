# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`secure-code-review`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: FLASK: password reset token lifecycle

- **Provenance:** Source: `securecode-web` | CWE: `CWE-640`
- **Context / Surface:** We're adding "forgot password" to our Flask API (it's the backend for a small B2B invoicing app, React frontend talks to it over JSON).
- **Root Cause / Analysis:** Missing security invariant for CWE-640.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 2: EXPRESS: nosql operator injection

- **Provenance:** Source: `securecode-web` | CWE: `CWE-943`
- **Context / Surface:** We're replacing passwords with emailed one-time codes in our Express 5 app (Node 22, official 'mongodb' driver, no Mongoose).
- **Root Cause / Analysis:** An unauthenticated attacker can log in as any user with a pending one-time code, including administrators, by sending a JSON operator object instead of the code.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 3: EXPRESS: insecure deserialization of rule bundle

- **Provenance:** Source: `securecode-web` | CWE: `CWE-502`
- **Context / Surface:** We run a small pricing service behind checkout (Node 22, Express 5). Right now every discount change is a PR plus a deploy, and the pricing team is tired of waiting on us.
- **Root Cause / Analysis:** Missing security invariant for CWE-502.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 4: JAVA: default admin credentials

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1392`
- **Context / Surface:** We've got a small internal admin portal written in plain Java 21 — no Spring, just the JDK 'HttpServer', because it ships as a sidecar container that ops spin up in each...
- **Root Cause / Analysis:** Any unauthenticated network attacker obtains full admin access on every deployment where the override variable was not set, with no user interaction and a publicly guessable credential.
- **Actionable Takeaway:** Replace the vulnerable java pattern with parameterized/validated state transitions.

## Case 5: EXPRESS: promo code single use enforcement

- **Provenance:** Source: `securecode-web` | CWE: `CWE-837`
- **Context / Surface:** We run a small merch store on Express 5 (Node 24). Cart and checkout already work; I need promo codes added before a campaign that starts next week.
- **Root Cause / Analysis:** Missing security invariant for CWE-837.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 6: JAVA: trust boundary violation

- **Provenance:** Source: `securecode-web` | CWE: `CWE-501`
- **Context / Surface:** We're splitting order lookup out of our monolith into its own service (Java 21, plain JDK 'HttpServer', no Spring, it sits behind our API gateway).
- **Root Cause / Analysis:** Any authenticated customer can read every other customer's order PII (email, shipping address) with a single extra form field, but the flaw does not grant write access or code execution.
- **Actionable Takeaway:** Replace the vulnerable java pattern with parameterized/validated state transitions.

## Case 7: EXPRESS: application level encryption

- **Provenance:** Source: `securecode-web` | CWE: `CWE-327`
- **Context / Surface:** We have a small notes feature in our API (Express 5 + TypeScript on Node 22). Users write private notes and read them back.
- **Root Cause / Analysis:** Missing security invariant for CWE-327.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 8: ASPNET-CORE: sql injection dynamic sql in stored function

- **Provenance:** Source: `securecode-web` | CWE: `CWE-89` | CVE: `CVE-2023-34362`
- **Context / Surface:** We're building the user admin page for our internal support console. Stack is ASP.NET Core minimal APIs on .NET 10, Postgres 17, Npgsql.
- **Root Cause / Analysis:** Missing security invariant for CWE-89.
- **Actionable Takeaway:** Replace the vulnerable aspnet-core pattern with parameterized/validated state transitions.
