# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ruby-on-rails-security`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: RAILS: idor file download

- **Provenance:** Source: `securecode-web` | CWE: `CWE-639`
- **Context / Surface:** Rails 8.1 API-only app, token auth via 'authenticate_with_http_token'. Customers upload invoices and bank statements;
- **Root Cause / Analysis:** Any authenticated user (self-service signup) can read every other customer's financial documents by changing a sequential id; confidentiality impact is total but integrity and availability are unaffected.
- **Actionable Takeaway:** Replace the vulnerable rails pattern with parameterized/validated state transitions.

## Case 2: RAILS: cancancan class level authorization idor

- **Provenance:** Source: `securecode-web` | CWE: `CWE-639`
- **Context / Surface:** We run a small agency project tracker as a Rails 8.1 JSON API (token auth, no Devise) and I just added CanCanCan so customers can't see each other's projects.
- **Root Cause / Analysis:** Any authenticated customer can read and modify every other customer's projects by iterating sequential ids, a full horizontal compromise of tenant data that still requires holding a valid account.
- **Actionable Takeaway:** Replace the vulnerable rails pattern with parameterized/validated state transitions.

## Case 3: RAILS: activerecord string where

- **Provenance:** Source: `securecode-web` | CWE: `CWE-89`
- **Context / Surface:** Quick sanity check before I ship this. We have a small Rails 8 API for our shop's product catalog (SQLite for now, Postgres later).
- **Root Cause / Analysis:** Unauthenticated, single-request injection on a public endpoint that reads any table the app's database user can access, including credential material such as reset tokens.
- **Actionable Takeaway:** Replace the vulnerable rails pattern with parameterized/validated state transitions.

## Case 4: RAILS: pundit missing object authorization

- **Provenance:** Source: `securecode-web` | CWE: `CWE-639`
- **Context / Surface:** Building the backend for a small project-tracking app: Rails 8.1, API-only, SQLite for now. Signup takes an email and hands back a key that the client sends as a header on every...
- **Root Cause / Analysis:** Any self-registered user can modify, delete, or take ownership of every other account's projects with one request per id, but cannot reach data outside the projects table or execute code.
- **Actionable Takeaway:** Replace the vulnerable rails pattern with parameterized/validated state transitions.

## Case 5: RAILS: client controlled session cookie

- **Provenance:** Source: `securecode-web` | CWE: `CWE-565` | CVE: `CVE-2025-5947`
- **Context / Surface:** We're on Rails 8.1 in API-only mode, with a React SPA served from the same origin (nginx in front, Puma behind it).
- **Root Cause / Analysis:** An unauthenticated remote attacker can read any user's protected profile by supplying its numeric id in a plain cookie, with no user interaction.
- **Actionable Takeaway:** Replace the vulnerable rails pattern with parameterized/validated state transitions.

## Case 6: RAILS: jwt hardcoded signing key

- **Provenance:** Source: `securecode-web` | CWE: `CWE-321`
- **Context / Surface:** I'm building a Rails 8 API ('config.api_only = true', Postgres) and adding JWT bearer-token auth so our iOS app can call the backend.
- **Root Cause / Analysis:** A guessable HMAC key committed to source lets anyone who reads or cracks it forge non-expiring tokens for any user_id, a remote authentication bypass for every account.
- **Actionable Takeaway:** Replace the vulnerable rails pattern with parameterized/validated state transitions.

## Case 7: RAILS: devise login attempt limiting

- **Provenance:** Source: `securecode-web` | CWE: `CWE-307`
- **Context / Surface:** We're adding customer accounts to our Rails 8 storefront with Devise. Prod is 3 Puma instances behind an AWS ALB, with RDS Postgres and an ElastiCache Redis we already use for...
- **Root Cause / Analysis:** An unauthenticated attacker can try passwords against any customer account without limit, so weak or reused passwords lead to account takeover; it is not a direct bypass because a valid password is still required.
- **Actionable Takeaway:** Replace the vulnerable rails pattern with parameterized/validated state transitions.

## Case 8: RAILS: mass assignment strong parameters

- **Provenance:** Source: `securecode-web` | CWE: `CWE-915`
- **Context / Surface:** We're building the accounts API for our app on Rails 8.1 (API-only, token auth, JSON in and out). Signup is 'POST /signup' and users edit their own profile with 'PATCH /me'.
- **Root Cause / Analysis:** Any self-registered user can make their own account an admin, or plant a token they know, with a single request. The damage is bounded by what the admin role can reach, and the attacker needs an account, but signup is open.
- **Actionable Takeaway:** Replace the vulnerable rails pattern with parameterized/validated state transitions.
