# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`type-juggling-and-loose-comparison`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: PHP Type Juggling 攻击方法论

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-843`
- **Context / Surface:** Source: github_security_md (zh)
- **Root Cause / Analysis:** --- name: php-type-juggling description: "PHP 类型杂耍（Type Juggling）和 Magic Hash 攻击方法论。当目标是 PHP 应用且存在密码比较、哈希校验、认证逻辑时使用。当看到 PHP '==' 松散比较、MD5/SHA1 哈希校验、strcmp 比较、JSON 输入处理、is_numeric 检查时必须使用。当错误登录泄露了输入的 MD5 哈希值时，这是 Magic Hash 的强信号，立即使用。CTF/渗透中 PHP 认证绕过最常见的漏洞类型之一。即使只是看到 PHP 5.x 或响应中包含
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Type Juggling 利用 Payload 与登录绕过技术

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-843`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # Type Juggling 利用 Payload 与登录绕过技术 ## PHP switch/case 类型混淆 'switch' 语句内部使用松散比较（'=='），可被类型杂耍利用： 'php switch ($_GET['action']) { case 0: admin_panel(); break; // 管理员操作 case 1: user_panel(); break; // 普通用户 } # 非数字字符串与 0 松散比较为 true（PHP 5.x/7.x），直接进入 case 0 curl "$TARGET/index.php?a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: PHP — Type Juggling

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-843`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # PHP — Type Juggling Type Juggling it’s a kind of bug that occurs only on PHP, mainly due to the way the language “compares” one thing to another. In PHP there’re a pair of operators that, although look similar, they do perform different tasks, those are == and ===. Double equal
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: PHP Type Juggling

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-843`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **PHP Type Juggling** is a vulnerability arising from PHP's loose type comparison system, where values of different types are automatically converted for comparison, potentially leading to authentication bypasses and other security issues. ### How Type Juggling Works 'php # Loo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: PHP Type Juggling

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-843`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # if a string starts with a non numerical character it will default to int(0) Another example is when PHP tries to interpret a string and its converted into PHP exponential notation 0e02342623422412516789. 0e2342623422412516789 equates to int(0) as well. If the number after the f
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: MantisBT vulnerable to authentication bypass for some passwords due to PHP type juggling

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-843`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** Due to an incorrect use of loose ('==') instead of strict ('===') comparison in the authentication code, PHP type juggling will cause interpretation of certain MD5 hashes as numbers, specifically those matching scientific notation. ### Impact On MantisBT instances configured to u
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
