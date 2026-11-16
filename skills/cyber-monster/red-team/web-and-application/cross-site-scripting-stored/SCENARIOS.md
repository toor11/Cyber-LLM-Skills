# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cross-site-scripting-stored`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Stored XSS in Wiki pages

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary I found Stored XSS using Wiki-specific Hierarchical link Markdown in Wiki pages. Steps to reproduce 1. Sign in to GitLab. 2. Open a Project page that you have permission to edit Wiki pages. 3. Open Wiki page. 4. Click "New page" button. 5.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Stored XSS on imgur profile

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello, I submitted a report on imgur, but the staff marked it as duplicate. #482841 I reviewed the report of the first submitted report. #381553 We are on the same situation and his case is already fixed because I tried visiting his site too which is https://12test.imgur.com/...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Stored XSS Vulnerability

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi there, I found a stored xss @ https://core.trac.wordpress.org/ Steps: 1. Go to https://core.trac.wordpress.org/ and login. (open new private window and login with another account) 2. Go to https://core.trac.wordpress.org/newticket and set a summary and description. 3.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Stored XSS in wordpress.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Stored XSS as a comment or as a post (body or title) at 'https://wordpress.com/read/feeds/{blog_id}/posts/{post_id}' 'https://yoursubdomain.wordpress.com' using the payload: Click Here=&gt;&lt;/iframe&gt;
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: HEY.com email stored XSS

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** An attacker can bypass the HEY.com HTML sanitizer and inject arbitrary unsafe HTML in emails. To reproduce the bug you have to send raw HTML-formatted email. You can do it e.g. with the Sendmail tool on Linux.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Stored XSS in Private Message component (BuddyPress)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description: WordPress version: **5.0.3** BuddyPress version: **4.1.0** Users with accounts can send private messages containing rendered HTML to other uses, this includes being able to execute javascript code via elements such as scripts, iframe etc.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Stored XSS in markdown via the DesignReferenceFilter

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary When rendering markdown, links to designs are parsed using the following 'link_reference_pattern': https://gitlab.com/gitlab-org/gitlab/-/blob/v13.12.1-ee/app/models/design_management/design.rb#L168 ruby def self.link_reference_pattern @link_reference_pattern //= begin...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Stored XSS via Kroki diagram

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary If Kroki has been enabled, it's possible to craft a 'pre' block so that arbitrary attributes can be injected into the resulting 'img' tag.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
