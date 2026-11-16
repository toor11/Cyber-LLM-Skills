# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`linux-privilege-escalation-sudo-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Hooking on Linux with LD_PRELOAD

- **Provenance:** Source: `CYBER_CPT/liveoverflow` | CWE: `CWE-269`
- **Context / Surface:** Source: liveoverflow (en)
- **Root Cause / Analysis:** **TLDR** Using the environment variable 'LD_PRELOAD' to hook and overwrite function calls to have fun in-game! ## Introduction We've been mostly trying to understand the game internals a little bit until now, maybe it's time we started with a small "hack". It was very important t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Homework

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-269`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** ## [Root Me] HTTP - Cookies - 웹해킹 / 쿠키변조 20점짜리 HTTP - Cookies 문제 난이도(레벨)을 보면 중간으로 표시되어있는데 사실 이 문제는 굉장히 쉬운 문제이다. Bob 이라는 사람이 사용자 이메일을 수집하기 위해 PHP 스크립트를 작성했다고 한다. 문제페이지에 접속하면 이렇게 Email을 입력하는 칸이 있다. 시험삼아 test@test.com 이라고 입력하고 send 버튼을 눌러보니 Email saved 라는 문구가 출력이됐다. Saved email adre
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Agile

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Agile is a box hosting a password manager solution. There’s a file read vulnerability in the application, and the Flask server is running in debug mode. I’ll use those to get execution on the box, which turns out to be a bit trickier than expected. From there, I’ll dump a user’s
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Joker

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Rooting Joker had three steps. The first was using TFTP to get the Squid Proxy config and creds that allowed access to a webserver listening on localhost that provided a Python console. To turn that into a shell, I'll have to enumerate the firewall and find that I can use UDP. I'
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Forgetful Commander

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-269`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # LoveTok HackTheBox Challenge - Writeup > True love is tough, and even harder to find. Once the sun has set, the > lights close and the bell has rung… you find yourself licking your wounds > and contemplating human existence. You wish to have somebody important in > your life to
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: LD_PRELOAD Rootkit on Chainsaw

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** There was something a bit weird going on with Chainsaw from HackTheBox. It turns out there’s a LD_PRELOAD rootkit running to hide the NodeJS processes that serve the smart contracts. Why? I have no idea. But since it’s a really neat concept, I wanted to pull it apart. Big thanks
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
