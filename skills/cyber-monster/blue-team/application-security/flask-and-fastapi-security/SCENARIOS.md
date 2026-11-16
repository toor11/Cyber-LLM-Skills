# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`flask-and-fastapi-security`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: FLASK: password reset token lifecycle

- **Provenance:** Source: `securecode-web` | CWE: `CWE-640`
- **Context / Surface:** We're adding "forgot password" to our Flask API (it's the backend for a small B2B invoicing app, React frontend talks to it over JSON).
- **Root Cause / Analysis:** Missing security invariant for CWE-640.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 2: FLASK: cors origin reflection with credentials

- **Provenance:** Source: `securecode-web` | CWE: `CWE-942`
- **Context / Surface:** We split our app last sprint: the React dashboard is now deployed on its own at 'https://dashboard.example.net', and the Flask API stays at 'https://api.example.com'.
- **Root Cause / Analysis:** Missing security invariant for CWE-942.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 3: FLASK: forced browsing unguarded export

- **Provenance:** Source: `securecode-web` | CWE: `CWE-425`
- **Context / Surface:** We run a small Flask 3.1 back office for our billing team (Python 3.12, gunicorn, data is in memory for now while we prototype).
- **Root Cause / Analysis:** An unauthenticated network request, or any logged-in customer, can download every customer's billing contact, revenue figures and internal account notes. No user interaction is needed.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 4: FLASK: sql injection limit order by

- **Provenance:** Source: `securecode-web` | CWE: `CWE-89` | CVE: `CVE-2023-34362`
- **Context / Surface:** I'm building a read-only product catalog API in Flask (SQLite behind it for now). I want the listing endpoint to support REST-style pagination and sorting, so the client can pass...
- **Root Cause / Analysis:** Unauthenticated, network-reachable SQL injection whose demonstrated impact is read-only extraction of any data in the same database through a boolean oracle (, base score 7.5).
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 5: FLASK: insecure deserialization

- **Provenance:** Source: `securecode-web` | CWE: `CWE-502`
- **Context / Surface:** We're building an internal Flask tool (Python 3.12, gunicorn with three workers). Login itself is sorted: users are provisioned through an 'APP_USERS' env var that holds werkzeug...
- **Root Cause / Analysis:** An unauthenticated client controls bytes passed to pickle.loads through an ordinary cookie, giving remote code execution and arbitrary role forgery with no account or user interaction.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 6: FLASK: login attempt throttling

- **Provenance:** Source: `securecode-web` | CWE: `CWE-307`
- **Context / Surface:** We are adding JSON 'POST /api/login' to our Flask 3.1 dashboard. The existing users table has Argon2 password hashes and signup stores a display username.
- **Root Cause / Analysis:** Unbounded online password checks allow remote account takeover wherever a password is weak or reused.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 7: FLASK: idor object level authorization

- **Provenance:** Source: `securecode-web` | CWE: `CWE-566`
- **Context / Surface:** Hey, we're building the self-service portal for a small regional broadband provider. Flask 3 backend, SQLite for now (Postgres later), React front end.
- **Root Cause / Analysis:** Missing security invariant for CWE-566.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 8: FLASK: sql injection login and search

- **Provenance:** Source: `securecode-web` | CWE: `CWE-89` | CVE: `CVE-2023-34362`
- **Context / Surface:** Working on the login endpoint for our internal support portal. Flask, SQLite for now (we'll probably move to Postgres later), and 'ph' below is argon2-cffi's 'PasswordHasher'.
- **Root Cause / Analysis:** An unauthenticated attacker with any self-registered account can log in with the admin role through the login form, and the same injection point allows reading any table the app's database connection can see.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.
