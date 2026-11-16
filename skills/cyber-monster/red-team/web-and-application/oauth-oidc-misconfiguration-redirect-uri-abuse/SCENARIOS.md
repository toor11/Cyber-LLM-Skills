# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`oauth-oidc-misconfiguration-redirect-uri-abuse`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Account Takeover in Periscope TV

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** When you login periscope.tv using twitter, and change the host header from 'www.periscope.tv' to 'attacker.com/www.periscope.tv', the oauth redirect destination will be 'attacker.com/www.periscope.tv', thus allowing attacker to send the oauth authorize link to...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Stealing Users OAuth authorization code via redirect_uri

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Path traversal in OAuth 'redirect_uri' which can lead to users authorization code being leaked to any malicious user. The following authorization code flow request is generated at booth login.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Path traversal, to RCE

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary This one is similar to #732330 but much simpler. A path traversal issue in GitLab package registry API allow an attacker to write any file at any location writable to user git in a GitLab server. Steps to reproduce 1. Enable package registry in your GitLab instance. 2.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: [portswigger.net] Path Traversal al /cms/audioitems

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Prelude. I wasn't going to report it, I thought it was your laboratory but after my first analysis this seems real. **Description** It's detected a path traversal as root user that allows to remote attackers see internal files as root.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Wordpress unzip_file path traversal

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary The Wordpress unzip_file function (https://codex.wordpress.org/Function_Reference/unzip_file) is vulnerable to path traversal when extracting zip files.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Zero day path traversal vulnerability in Grafana 8.x allows unauthenticated arbitrary local file read

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hi team, I've found a path traversal issue in the Grafana instances hosted on the Aiven platforms. With the path traversal it's possible for an unauthenticated user to read arbitrary files on the server. Steps To Reproduce: 1. Login at https://console.aiven.io 1.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Path traversal in Nuget Package Registry

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary There's a path traversal issue in Nuget package registry which was released to GitLab-EE recently. The issue allows an attacker to create any file with an extension “.nupkg” in the filesystem.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
