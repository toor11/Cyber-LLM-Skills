# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`code-injection-and-eval`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Panorama UI XSS leads to Remote Code Execution via Kick/Disconnect Message

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Overview Counter-Strike: Global Offensive's UI is built of a framework called Panorama which is heavily influenced by modern HTML/CSS with JS capabilities. Because of these properties, the UI becomes easily vulnerable to different types of code injection, most notably XSS.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: CVE-2023-5528: Insufficient input sanitization in in-tree storage plugin leads to privilege escalation on

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2023-5528`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** This is an imported report from the email i have sent a month ago about a code injection vulnerability The vulnerability was assigned as CVE-2023-5528 As a reference i have talked with Balaji from the k8 team.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: CSS Injection to disable app & potential message exfil

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Tested on Slack for MacOS v4.0.2 - I've marked this as code injection since there was no "css injection" 1. In the app go to Preferences -> Sidebar 2. Enable custom theming 3. Set the column BG to '#FFFFFF;} html {display:none;}' 4.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: RCE in 'Copy as Node Request' BApp via code injection

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description 'Copy as Node Request' is a burp suite extension that allows users to copy requests as Node.js code. Due to improper sanitization of cookie, it's possible to inject arbitrary Node.js code in copied text, which may lead remote code execution with a significant amount...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Code injection in macOS Desktop Client

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Vulnerability description I've identified a code injection vulnerability in your macOS desktop client. Any malicious application, running with standard user permissions is able to exploit this vulnerability and execute code in your application's context.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: code injection, steam chat client

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** The steam chat client allows oEmbed, apparently based on a whitelist. One of the whitelisted oEmbedis codepen. When a codepen is created, it can be sent as a link to another steam user, and the code inside the codepen will execute within the privileged Steam Chat context.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Code injection in https://www.semrush.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** INTRODUCES: -With a direct error on the homepage, it is easy to trick the victim into accessing a fake page from the attacker STEP: Step: Send url with payload to victim:...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Code Injection via Insecure Yaml.load

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Report Submission Form Summary: The Kubernetes repo and tool, test-infra, uses the insecure yaml.load() function to set or update the 'Gubernator' configuration with a yaml file which allows for code injection.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
