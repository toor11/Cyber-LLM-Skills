# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`web-recon-and-content-discovery-archive-and-osint-recon`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: JumpCloud API Key leaked via Open Github Repository.

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** Open Github Repo Leaking Starbucks JumbCloud API Key **Description:** Team, While going through Github search I discovered a public repository which contains Jumbcloud API Key of Starbucks. Repo: https://github.com/██████████/Project.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: gau URL 历史收集方法论

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-20`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** --- name: gau-urlfetch description: "使用 gau 从历史数据源收集目标域名的已知 URL。当需要发现目标的历史 URL、隐藏端点、参数、API 路径时使用。gau 聚合 Wayback Machine、Common Crawl、OTX、URLScan 四大数据源。任何涉及 URL 收集、攻击面发现、参数发现、历史页面收集的场景都应使用此技能" metadata: tags: "gau,url,fetch,URL收集,Wayback,历史URL,攻击面,参数发现,OSINT,信息收集" category: "tool"
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Waybackurls

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-20`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** ### Source https://github.com/tomnomnom/waybackurls ### Get all URLs from wayback machine, use file that contains tld domains ' cat .txt / waybackurls '
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
