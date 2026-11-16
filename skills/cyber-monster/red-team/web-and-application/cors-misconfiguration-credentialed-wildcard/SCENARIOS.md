# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cors-misconfiguration-credentialed-wildcard`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Usage

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-942`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Usage starts with a blind SQL injection in a password reset form that I can use to dump the database and find the admin login. The admin panel is made with Laravel-Admin, which has a vulnerability in it that allows uploading a PHP webshell as a profile picture by changing the fil
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Gofer

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-942`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Gofer starts with a proxy that requires auth. I’ll bypass this using different HTTP verbs, and get access to the proxy that allows for gopher protocol. I’ll use that to interact with an internal SMTP server and send a phishing email to one of the users with a LibreOffice Writer (
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: DevVortex

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-942`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DevVortex starts with a Joomla server vulnerable to an information disclosure vulnerability. I'll leak the users list as well as the database connection password, and use that to get access to the admin panel. Inside the admin panel, I'll show how to get execution both by modifyi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Node

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-942`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Node is about enumerating a Express NodeJS application to find an API endpoint that shares too much data., including user password hashes. To root the box, there’s a simple return to libc buffer overflow exploit. I had some fun finding three other ways to get the root flag, as we
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Analytics

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-942`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Analytics starts with a webserver hosting an instance of Metabase. There’s a pre-auth RCE exploit that involves leaking a setup token and using it to start the server setup, injecting into the configuration to get code execution. Inside the Metabase container, I’ll find creds in
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Format

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-942`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Format hosts a primitive opensource microblogging site. I’ll abuse post creation to get arbitrary read and write on the host, and use that along with a proxy_pass bug to poison Redis, giving my account “pro” status. With the upgraded status, I can access a writable directory that
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
