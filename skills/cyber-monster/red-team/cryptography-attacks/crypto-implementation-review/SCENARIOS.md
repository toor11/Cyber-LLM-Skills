# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`crypto-implementation-review`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: EXPRESS: application level encryption

- **Provenance:** Source: `securecode-web` | CWE: `CWE-327`
- **Context / Surface:** We have a small notes feature in our API (Express 5 + TypeScript on Node 22). Users write private notes and read them back.
- **Root Cause / Analysis:** Missing security invariant for CWE-327.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 2: GO: aes ecb token forgery

- **Provenance:** Source: `securecode-web` | CWE: `CWE-327`
- **Context / Surface:** We're adding guest access to our partner portal. The service uses Go 1.26 with plain net/http and no database for this part.
- **Root Cause / Analysis:** An unauthenticated user can forge an admin pass from the public signup endpoint and read partner payout account data, though the impact is confined to this portal's data.
- **Actionable Takeaway:** Replace the vulnerable go pattern with parameterized/validated state transitions.

## Case 3: ASPNET-CORE: predictable reset token

- **Provenance:** Source: `securecode-web` | CWE: `CWE-337`
- **Context / Surface:** I'm adding "forgot password" to our account service. It's an ASP.NET Core minimal API on .NET 10, with users in memory for now (we'll move to a real DB later) and a stub mailer we...
- **Root Cause / Analysis:** An unauthenticated attacker who knows a victim's email can reproduce that victim's password-reset token and take over the account with no user interaction .
- **Actionable Takeaway:** Replace the vulnerable aspnet-core pattern with parameterized/validated state transitions.

## Case 4: EXPRESS: password hashing

- **Provenance:** Source: `securecode-web` | CWE: `CWE-916`
- **Context / Surface:** Working on the accounts service for our booking app (Node 22, Express 5, ESM). I need: - 'POST /api/register' with '{ email, password }' - 'POST /api/login', which just returns...
- **Root Cause / Analysis:** Missing security invariant for CWE-916.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 5: FLASK: hardcoded encryption key

- **Provenance:** Source: `securecode-web` | CWE: `CWE-321`
- **Context / Surface:** We run a small patient portal (Flask, Python 3.12). Patients want to send a lab result to another doctor, so I added "share links": the link carries an encrypted token with the...
- **Root Cause / Analysis:** Anyone holding a copy of the source can forge share links for any patient record and decrypt intercepted ones without authenticating, but the attack first requires access to the source or a build artifact.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 6: ASPNET-CORE: aes ecb field encryption

- **Provenance:** Source: `securecode-web` | CWE: `CWE-327`
- **Context / Surface:** We're building a small internal "field vault" service on .NET 10 / minimal APIs. Other services (billing, payroll, support...) POST a sensitive value like a tax ID or bank account...
- **Root Cause / Analysis:** Missing security invariant for CWE-327.
- **Actionable Takeaway:** Replace the vulnerable aspnet-core pattern with parameterized/validated state transitions.

## Case 7: NEXTJS: jwt in localstorage

- **Provenance:** Source: `securecode-web` | CWE: `CWE-922`
- **Context / Surface:** I'm building a small notes app on Next.js 16 (App Router, route handlers are the whole API, no separate backend yet). Login checks the password and signs a JWT with 'jose'.
- **Root Cause / Analysis:** Exploitation needs a separate script-execution foothold (XSS or a compromised client-side dependency), but once present it turns into off-device account takeover that outlives logout for the token's full 7-day lifetime.
- **Actionable Takeaway:** Replace the vulnerable nextjs pattern with parameterized/validated state transitions.

## Case 8: EXPRESS: weak tls protocol and cipher configuration

- **Provenance:** Source: `securecode-web` | CWE: `CWE-327`
- **Context / Surface:** We're replacing the old PHP endpoint that our warehouse handhelds post barcode scans to. New version is Node 22 + Express 5.
- **Root Cause / Analysis:** Exploiting the re-enabled TLS 1.0/1.1 and static-RSA suites requires a network position on the device network plus either a legacy client session or later theft of the server key, but the payoff is reusable device bearer tokens.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.
