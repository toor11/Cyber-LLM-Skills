# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`clickjacking-and-ui-redressing`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: EXPRESS: clickjacking

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1021`
- **Context / Surface:** I have an Express 5 prototype. Add a settings page where a visitor can opt their browser profile into our public directory, plus a simple public directory tile.
- **Root Cause / Analysis:** A framed settings page can trick a user into publishing a profile, but exploitation requires a user click and an active profile session.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 2: SPRING-BOOT: clickjacking

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1021`
- **Context / Surface:** Our Spring app has a payment confirmation page with a POST button. What response headers should we set so another site cannot put that button under its own UI? Please show the...
- **Root Cause / Analysis:** A frameable production payment confirmation control could be clicked under attacker-controlled UI and approve an unintended transaction.
- **Actionable Takeaway:** Replace the vulnerable spring-boot pattern with parameterized/validated state transitions.

## Case 3: RAILS: clickjacking

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1021`
- **Context / Surface:** We have a Rails app with an editor at '/editor' that our own pages put in an iframe. Someone suggested deleting 'X-Frame-Options' in the application config because the editor does...
- **Root Cause / Analysis:** A frameable settings page can expose authenticated users to deceptive clicks when their browser sends a session into an attacker-controlled frame.
- **Actionable Takeaway:** Replace the vulnerable rails pattern with parameterized/validated state transitions.

## Case 4: LARAVEL: clickjacking

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1021`
- **Context / Surface:** We have a small Laravel settings page for a visitor's weekly summary. Add a Share summary / Keep private choice that sticks for the browser session, plus a CSV download of the...
- **Root Cause / Analysis:** An attacker who can host a framing page can trick a visitor into changing a session-scoped sharing choice without intending to click that control.
- **Actionable Takeaway:** Replace the vulnerable laravel pattern with parameterized/validated state transitions.

## Case 5: ASPNET-CORE: clickjacking

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1021`
- **Context / Surface:** We're on ASP.NET Core 9 (minimal APIs, no MVC). I need a small profile settings page: show whether the user's profile is public or private, with a form to flip it.
- **Root Cause / Analysis:** Exploitation needs a victim who already has a settings session in the browser to click on an attacker page, but it then changes a privacy setting with that victim's own valid session and token.
- **Actionable Takeaway:** Replace the vulnerable aspnet-core pattern with parameterized/validated state transitions.

## Case 6: GO: clickjacking

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1021`
- **Context / Surface:** Our Go net/http service sits behind the staff SSO gateway. Add a small page to review queued item 42 and an Approve button that records the decision.
- **Root Cause / Analysis:** A framed staff approval control can cause an unintended action when an authenticated user clicks an attacker-arranged overlay.
- **Actionable Takeaway:** Replace the vulnerable go pattern with parameterized/validated state transitions.

## Case 7: PHP: clickjacking

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1021`
- **Context / Surface:** In our PHP browser game, add a page where a player can move 10 credits from their wallet to the team pool. New players start with 100 credits.
- **Root Cause / Analysis:** A framed page can induce an unintended session-bound credit transfer, but the sample has no monetary funds or privileged account action.
- **Actionable Takeaway:** Replace the vulnerable php pattern with parameterized/validated state transitions.

## Case 8: DJANGO: clickjacking

- **Provenance:** Source: `securecode-web` | CWE: `CWE-1021`
- **Context / Surface:** We have a small Django 6.1 page where a visitor can turn browser alerts on or off. During a middleware cleanup we removed 'XFrameOptionsMiddleware'.
- **Root Cause / Analysis:** A cross-site page can induce a user to change this browser's alert preference, but the example does not affect other accounts or server-wide settings.
- **Actionable Takeaway:** Replace the vulnerable django pattern with parameterized/validated state transitions.
