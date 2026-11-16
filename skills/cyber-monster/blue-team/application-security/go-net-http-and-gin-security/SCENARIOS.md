# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`go-net-http-and-gin-security`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: GIN: untrusted module source fetch

- **Provenance:** Source: `securecode-web` | CWE: `CWE-918`
- **Context / Surface:** We're building a small internal "module fetcher" in Go for our platform team. Teams send it a Terraform module source address (same syntax as Terraform's 'source =' lines), it...
- **Root Cause / Analysis:** An unauthenticated caller can make the vulnerable service fetch repositories from unapproved hosts and local file transport, then pass their contents into a module pipeline; the offline HTTP tests observe those fetches.
- **Actionable Takeaway:** Replace the vulnerable gin pattern with parameterized/validated state transitions.

## Case 2: GIN: exposed debug route

- **Provenance:** Source: `securecode-web` | CWE: `CWE-489`
- **Context / Surface:** I have a small Gin catalog API for our storefront. Please add a health check and a product lookup by SKU. Ops also wants a quick catalog snapshot endpoint for rollout checks.
- **Root Cause / Analysis:** An unauthenticated diagnostic route exposes internal supplier and cost data from the service, but the shown code has no write or code execution path.
- **Actionable Takeaway:** Replace the vulnerable gin pattern with parameterized/validated state transitions.

## Case 3: GIN: unpinned third party script dependency

- **Provenance:** Source: `securecode-web` | CWE: `CWE-829`
- **Context / Surface:** Need a small support page in our Gin service. Support keeps asking customers "what browser are you on?" and getting answers like "the blue one".
- **Root Cause / Analysis:** A hijacked or replaced script runs with full privileges on the application's origin for every visitor, but exploitation requires compromising the upstream package or CDN path first rather than the application directly.
- **Actionable Takeaway:** Replace the vulnerable gin pattern with parameterized/validated state transitions.

## Case 4: GIN: unreviewed module replacement

- **Provenance:** Source: `securecode-web` | CWE: `CWE-829`
- **Context / Surface:** Our Gin product API calls a summary formatter that the catalog team owns. They're partway through moving it to a new module, so someone on my team added a Makefile step that...
- **Root Cause / Analysis:** A directory replace compiles unpinned code from a branch outside the team's review into the server process, where it can read any data passed to it or reachable from the process.
- **Actionable Takeaway:** Replace the vulnerable gin pattern with parameterized/validated state transitions.

## Case 5: GIN: order by sql injection

- **Provenance:** Source: `securecode-web` | CWE: `CWE-89`
- **Context / Surface:** Our Gin product endpoint needs 'sort=id/name/price' and 'order=asc/desc'. The data comes from SQLite for now.
- **Root Cause / Analysis:** An unauthenticated sort expression can read otherwise private database values through a repeatable response-order oracle.
- **Actionable Takeaway:** Replace the vulnerable gin pattern with parameterized/validated state transitions.

## Case 6: GIN: outdated cors middleware

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1395` | CVE: `CVE-2019-25211`
- **Context / Surface:** We have a Gin API for saved budget drafts. Our planning UI at https://example.com should be able to POST a short draft and read it back later using its browser cookie.
- **Root Cause / Analysis:** A vulnerable CORS dependency can expose cookie-scoped responses to a lookalike browser origin when credentialed cross-origin requests are possible.
- **Actionable Takeaway:** Replace the vulnerable gin pattern with parameterized/validated state transitions.

## Case 7: GIN: outdated gin client ip trust

- **Provenance:** Source: `securecode-web` | CWE: `CWE-348` | CVE: `CVE-2020-28483`
- **Context / Surface:** Our Go service uses Gin. Add a quarterly report: everyone can see the order count at '/reports/summary', but '/reports/detail' should show the margin only to our office egress IP.
- **Root Cause / Analysis:** A remote caller can forge the client IP that the route trusts and read an IP-restricted report; the outdated Gin release offers no trusted-proxy control to prevent it.
- **Actionable Takeaway:** Replace the vulnerable gin pattern with parameterized/validated state transitions.

## Case 8: GIN: nosql injection

- **Provenance:** Source: `securecode-web` | CWE: `CWE-943`
- **Context / Surface:** We're using Gin with Redis Search for a small cache browser. Can you add a source filter so the list endpoint returns the matching cache entries? Each deployment serves one...
- **Root Cause / Analysis:** A crafted source filter can escape the tenant search clause and expose another tenant's indexed entry.
- **Actionable Takeaway:** Replace the vulnerable gin pattern with parameterized/validated state transitions.
