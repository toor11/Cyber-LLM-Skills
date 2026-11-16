# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`secure-code-review-access-control-review`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: RAILS: idor file download

- **Provenance:** Source: `securecode-web` | CWE: `CWE-639`
- **Context / Surface:** Rails 8.1 API-only app, token auth via 'authenticate_with_http_token'. Customers upload invoices and bank statements;
- **Root Cause / Analysis:** Any authenticated user (self-service signup) can read every other customer's financial documents by changing a sequential id; confidentiality impact is total but integrity and availability are unaffected.
- **Actionable Takeaway:** Replace the vulnerable rails pattern with parameterized/validated state transitions.

## Case 2: EXPRESS: client controlled role authorization

- **Provenance:** Source: `securecode-web` | CWE: `CWE-807`
- **Context / Surface:** Working on the internal admin side of our API (TypeScript, Express 5, Node 22). Login already works: sessions are an opaque 'sid' cookie backed by a server-side store, and the...
- **Root Cause / Analysis:** Any authenticated low-privilege user can grant themselves admin with one edited cookie over the network, gaining full read and write over user accounts; an account is required, so it is not CRITICAL.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 3: PHP: mass assignment of account fields

- **Provenance:** Source: `securecode-web` | CWE: `CWE-915`
- **Context / Surface:** I'm adding 'PATCH /api/me' to a small PHP 8.3 profile service. Records have a display name, plan, role, daily API limit, and nested settings.
- **Root Cause / Analysis:** A member can change their own role to admin and read other accounts through the included admin endpoint.
- **Actionable Takeaway:** Replace the vulnerable php pattern with parameterized/validated state transitions.

## Case 4: GO-NET-HTTP: forced browsing security by obscurity

- **Provenance:** Source: `securecode-web` | CWE: `CWE-425`
- **Context / Surface:** Quick sanity check before I ship something. We have a small Go service (stdlib 'net/http', Go 1.23 routing) that backs our storefront.
- **Root Cause / Analysis:** An unauthenticated remote attacker who learns the leaked path can read all customer emails and disable any account, but impact is confined to this service's account data rather than full system compromise.
- **Actionable Takeaway:** Replace the vulnerable go-net-http pattern with parameterized/validated state transitions.

## Case 5: SPRING-BOOT: http method scoped authorization

- **Provenance:** Source: `securecode-web` | CWE: `CWE-863`
- **Context / Surface:** Spring Boot 4 / Java 21, small internal admin API with HTTP Basic (it sits behind our VPN, users and roles live in our own table).
- **Root Cause / Analysis:** Any authenticated low-privilege user can grant themselves ADMIN or delete accounts with a single request; it requires valid credentials and the API is internal, which keeps it below CRITICAL.
- **Actionable Takeaway:** Replace the vulnerable spring-boot pattern with parameterized/validated state transitions.

## Case 6: SQLALCHEMY: orm relationship traversal overexposure

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1220`
- **Context / Surface:** We're building the clinician portal for a small outpatient clinic group. Stack is Flask 3.1 + SQLAlchemy 2.0 (typed 'Mapped[]' models), SQLite locally and Postgres in prod, React...
- **Root Cause / Analysis:** Missing security invariant for CWE-1220.
- **Actionable Takeaway:** Replace the vulnerable sqlalchemy pattern with parameterized/validated state transitions.

## Case 7: ASPNET-CORE: client side only admin authorization

- **Provenance:** Source: `securecode-web` | CWE: `CWE-862`
- **Context / Surface:** Building a small internal admin panel on ASP.NET Core 10 (minimal APIs, cookie auth, no Identity).
- **Root Cause / Analysis:** Any authenticated low-privilege user can read every account's details, disable other accounts, and grant themselves the admin role with plain HTTP requests ; it requires a valid account, which keeps it below CRITICAL.
- **Actionable Takeaway:** Replace the vulnerable aspnet-core pattern with parameterized/validated state transitions.

## Case 8: APOLLO-SERVER: graphql field authz

- **Provenance:** Source: `securecode-web` | CWE: `CWE-862`
- **Context / Surface:** We're building the internal employee directory on Apollo Server 5 (Node 22, plain ESM, no Express).
- **Root Cause / Analysis:** Any authenticated employee can read every colleague's salary and performance reviews with a single query; confidentiality impact is high but it requires a valid internal account and does not grant write access.
- **Actionable Takeaway:** Replace the vulnerable apollo-server pattern with parameterized/validated state transitions.
