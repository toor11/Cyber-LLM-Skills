# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`session-and-token-lifecycle`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: FLASK: password reset token lifecycle

- **Provenance:** Source: `securecode-web` | CWE: `CWE-640`
- **Context / Surface:** We're adding "forgot password" to our Flask API (it's the backend for a small B2B invoicing app, React frontend talks to it over JSON).
- **Root Cause / Analysis:** Missing security invariant for CWE-640.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 2: JAVA: default admin credentials

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1392`
- **Context / Surface:** We've got a small internal admin portal written in plain Java 21 — no Spring, just the JDK 'HttpServer', because it ships as a sidecar container that ops spin up in each...
- **Root Cause / Analysis:** Any unauthenticated network attacker obtains full admin access on every deployment where the override variable was not set, with no user interaction and a publicly guessable credential.
- **Actionable Takeaway:** Replace the vulnerable java pattern with parameterized/validated state transitions.

## Case 3: ASPNET-CORE: jwt signature not verified

- **Provenance:** Source: `securecode-web` | CWE: `CWE-347`
- **Context / Surface:** We've got a small invoices API on .NET 10 (minimal APIs, no controllers). The mobile app is moving off cookies, so it'll log in once, get a token string back, and send that token...
- **Root Cause / Analysis:** Missing security invariant for CWE-347.
- **Actionable Takeaway:** Replace the vulnerable aspnet-core pattern with parameterized/validated state transitions.

## Case 4: EXPRESS: mfa step bypass

- **Provenance:** Source: `securecode-web` | CWE: `CWE-308`
- **Context / Surface:** We're on Express 5 with express-session. Last sprint we shipped the page in account settings where people scan a QR code into the code app on their phone (Google's app, 1Password,...
- **Root Cause / Analysis:** Anyone holding a user's password gets a fully authenticated session without the second factor, defeating the control for every enrolled user, though a valid password is still required.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 5: PHP: jwt hardcoded hmac key

- **Provenance:** Source: `securecode-web` | CWE: `CWE-321`
- **Context / Surface:** I'm putting together a small accounts API in plain PHP 8.3 (no framework, just composer + 'firebase/php-jwt') that our mobile app will talk to.
- **Root Cause / Analysis:** A guessable hard-coded HS256 key lets any remote party sign tokens for any user, including administrators, with no interaction and low complexity.
- **Actionable Takeaway:** Replace the vulnerable php pattern with parameterized/validated state transitions.

## Case 6: SPRING-BOOT: password reset token lifecycle

- **Provenance:** Source: `securecode-web` | CWE: `CWE-640`
- **Context / Surface:** We're adding self-service password reset to our account service (Spring Boot 4, Java 21). Before I open the PR, our security lead asked me to have someone look at the token...
- **Root Cause / Analysis:** Any exposed copy of a reset link, however old or already used, gives full account takeover without the password, but the attacker must first obtain such a link.
- **Actionable Takeaway:** Replace the vulnerable spring-boot pattern with parameterized/validated state transitions.

## Case 7: ASPNET-CORE: unauthenticated first run admin setup

- **Provenance:** Source: `securecode-web` | CWE: `CWE-306` | CVE: `CVE-2023-20198`
- **Context / Surface:** We're turning our inventory dashboard into a self-hosted product. Backend is ASP.NET Core minimal APIs on .NET 10, SQLite for storage, and cookie login.
- **Root Cause / Analysis:** An unauthenticated network attacker can create an administrator account with a single request, giving full control of the application.
- **Actionable Takeaway:** Replace the vulnerable aspnet-core pattern with parameterized/validated state transitions.

## Case 8: EXPRESS: remember me token

- **Provenance:** Source: `securecode-web` | CWE: `CWE-784`
- **Context / Surface:** We've got a small Express 5 app (Node 22) with email/password login and an in-memory session cookie.
- **Root Cause / Analysis:** Missing security invariant for CWE-784.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.
