# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`oauth-oidc-misconfiguration`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Stealing Users OAuth authorization code via redirect_uri

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Path traversal in OAuth 'redirect_uri' which can lead to users authorization code being leaked to any malicious user. The following authorization code flow request is generated at booth login.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Security bug https://bugzilla.mozilla.org/oauth/authorize - CRLF Header injection via "redirect_uri" para

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: CRLF / HTTP Header Injection. Allows you to set any headers/etc (Set-Cookie...) Page: https://bugzilla.mozilla.org/oauth/authorize Parameter: redirect_uri Steps To Reproduce: PoC - does not require authorization: 1.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: [auth2.zomato.com] Reflected XSS at 'oauth2/fallbacks/error' / ORY Hydra an OAuth 2.0 and OpenID Connect

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Heyy there, I have found a xss in auth2.zomato.com **Full url:**https://auth2.zomato.com/oauth2/fallbacks/error?error=xss&error_description=xss&error_hint=xss **Vulnerable Parameters:** All available parameters are vulnerable **XSS Payload:** '<marquee loop%3d1 width%3d0...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Stealing Users OAUTH Tokens via redirect_uri

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, I would like to report an Open redirection on oauth redirect_uri which can lead to users oauth tokens being leaked to any malicious user. **Detail** During the OAUTH flow, the redirect_uri on https://accounts.bistudio.com is not properly validating that the URL given is...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Oauth flow on the comments widget login can lead to the access code leakage

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description Hello. Here is a keyword: 'frog' I discovered an little Oauth flow in the comments widget authentication process using redirect_uri manipulations.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Shop App - Attacker is able to intercept authorization code during authentication (OAuth) and is able to

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Deep linking Mobile apps have a unique vulnerability that is non-existent in the web: deep linking. Deep linking is a way of sending data directly to a native application from an outside source.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: [user_oidc] Stored XSS via Authorization Endpoint - Safari-Only

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: The OpenID Connect User Backend allows users to login to Nextcloud using SSO. A workaround that was apparently implemented for the *Safari* browser enables stored Cross-Site-Scripting (XSS).
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: n8n has Open Redirect in MCP OAuth Consent Flow

- **Provenance:** Source: `CYBER_CPT/gh_security_lab`
- **Context / Surface:** CodeQL / Audit Case (en)
- **Root Cause / Analysis:** Impact The '/mcp-oauth/register' endpoint accepted OAuth client registrations without authentication, allowing arbitrary 'redirect_uri' values to be registered.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.
