# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`graphql-security-batching-and-dos`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Unattended

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-20`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Users rated Unattended much harder than the Medium rating it was released under. I think that’s because the SQLI vulnerability was easy to find, but dumping the database would take forever. So the trick was knowing when to continue looking and identify the NGINX vulnerability to
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: GraphQL Batching Attack

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-20`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **GraphQL Batching Attack** exploits GraphQL's ability to execute multiple operations in a single request. Attackers abuse this to bypass rate limiting, brute-force credentials, or cause denial of service. ### Attack Types #### Query Batching for Brute Force 'json # Single requ
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Powershell注意别名风险

- **Provenance:** Source: `CYBER_CPT/pstips` | CWE: `CWE-20`
- **Context / Surface:** Source: pstips (zh)
- **Root Cause / Analysis:** # Powershell注意别名风险 支持所有PS版本 在Powershell中别名在执行命令中享受优先待遇，所以你的命令如果产生了歧义，Powershell将总是优先执行别名。 这是非常危险：如果你使用了其它方法改变PS中的环境或添加有歧义的别名，你的脚本将可能出现完全不一样的情况。 这里有一个简单的命令添加一个别名让Get-Chidltem指向PING.EXE： 'powershell Set-Alias -Name Get-ChildItem -Value ping ' 这将改变了一切东西：现在PING不仅仅是将Get-childitem替
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Best Schools

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-20`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Best Schools ## Background An anonymous company has decided to publish a ranking of the best schools, and it is based on the number of clicks on a button! Make sure you get the 'Flag CyberSecurity School' in first place and you'll get your reward! > Deploy on [[deploy.heroctf.f
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Powershell使用别名运行WINDOWS组件 2

- **Provenance:** Source: `CYBER_CPT/pstips` | CWE: `CWE-20`
- **Context / Surface:** Source: pstips (mixed)
- **Root Cause / Analysis:** # Powershell使用别名运行WINDOWS组件 [2] (#tc-comment-title "2 评论开启 Powershell使用别名运行WINDOWS组件") [2014年2月25日] (https://www.pstips.net/2014/02/25 "下午 10:39") 在 [Powershell] (https://www.pstips.net/cat/powershell "参看所有文章 Powershell") 标签 [别名] (https://www.pstips.net/tag/%E5%88%AB%E5%90%8D "参看所有文章
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Aliases

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-20`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** - Terminator Configuration / Zsh: https://guide.offsecnewbie.com/kali-configuration/terminator-shortcuts - CherryTree template: https://guide.offsecnewbie.com/cherrytree-oscp-template # Aliases ' ## ALIASES alias vpn='openvpn /root/pwnshare/VPN/OS-XXXXX-PWK.ovpn' alias rdp='rde
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
