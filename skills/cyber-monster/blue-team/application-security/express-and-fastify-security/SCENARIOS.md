# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`express-and-fastify-security`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: EXPRESS: nosql operator injection

- **Provenance:** Source: `securecode-web` | CWE: `CWE-943`
- **Context / Surface:** We're replacing passwords with emailed one-time codes in our Express 5 app (Node 22, official 'mongodb' driver, no Mongoose).
- **Root Cause / Analysis:** An unauthenticated attacker can log in as any user with a pending one-time code, including administrators, by sending a JSON operator object instead of the code.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 2: EXPRESS: insecure deserialization of rule bundle

- **Provenance:** Source: `securecode-web` | CWE: `CWE-502`
- **Context / Surface:** We run a small pricing service behind checkout (Node 22, Express 5). Right now every discount change is a PR plus a deploy, and the pricing team is tired of waiting on us.
- **Root Cause / Analysis:** Missing security invariant for CWE-502.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 3: EXPRESS: promo code single use enforcement

- **Provenance:** Source: `securecode-web` | CWE: `CWE-837`
- **Context / Surface:** We run a small merch store on Express 5 (Node 24). Cart and checkout already work; I need promo codes added before a campaign that starts next week.
- **Root Cause / Analysis:** Missing security invariant for CWE-837.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 4: EXPRESS: application level encryption

- **Provenance:** Source: `securecode-web` | CWE: `CWE-327`
- **Context / Surface:** We have a small notes feature in our API (Express 5 + TypeScript on Node 22). Users write private notes and read them back.
- **Root Cause / Analysis:** Missing security invariant for CWE-327.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 5: EXPRESS: client controlled role authorization

- **Provenance:** Source: `securecode-web` | CWE: `CWE-807`
- **Context / Surface:** Working on the internal admin side of our API (TypeScript, Express 5, Node 22). Login already works: sessions are an opaque 'sid' cookie backed by a server-side store, and the...
- **Root Cause / Analysis:** Any authenticated low-privilege user can grant themselves admin with one edited cookie over the network, gaining full read and write over user accounts; an account is required, so it is not CRITICAL.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 6: EXPRESS: prototype pollution deep path setter

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1321` | CVE: `CVE-2020-8203`
- **Context / Surface:** Our settings page got rebuilt as a dynamic form, and every input's 'name' is the dot-path of the setting it controls ('display.theme', 'notifications.email.weekly', etc.).
- **Root Cause / Analysis:** A regular account can pollute Object.prototype for the whole process and make this app grant access to an admin-only audit log.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 7: EXPRESS: outdated lodash merge prototype pollution

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1321` | CVE: `CVE-2018-3721`
- **Context / Surface:** Product wants a "preview" button on our feature-flag settings page: a signed-in user picks a few settings (theme, checkout variant, search engine, etc.), we merge their picks over...
- **Root Cause / Analysis:** One request from any authenticated member pollutes Object.prototype for the whole process and grants admin-only access to every non-staff account until restart;
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 8: EXPRESS: xml external entities

- **Provenance:** Source: `securecode-web` | CWE: `CWE-611`
- **Context / Surface:** We take purchase orders from B2B partners as XML. Their systems POST straight to an Express 5 endpoint, we pull out a few fields, and we hand back JSON so they can confirm what we...
- **Root Cause / Analysis:** One unauthenticated request yields arbitrary file read as the service user (credentials, config), but not direct code execution, so high rather than critical.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.
