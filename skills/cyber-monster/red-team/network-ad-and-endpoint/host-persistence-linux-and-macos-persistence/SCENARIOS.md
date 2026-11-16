# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`host-persistence-linux-and-macos-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Curling

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Curling was a solid box easy box that provides a chance to practice some basic enumeration to find a password, using that password to get access to a Joomla instance, and using the access to get a shell. With a shell, I'll find a compressed and encoded backup file, that after a b
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Shrek

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Shrek is another 2018 HackTheBox machine that is more a string of challenges as opposed to a box. I’ll find an uploads page in the website that doesn’t work, but then also find a bunch of malware (or malware-ish) files in the uploads directory. One of them contains a comment abou
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: RE

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** RE was a box I was really excited about, and I was crushed when the final privesc didn’t work on initial deployment. Still, it got patched, and two unintended paths came about as well, and everything turned out ok. I’ll approach this write-up how I expected people to solve it, an
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Helpline Windows

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I luckily decided to use Helpline as my test run for Commando VM. That allowed me to avoid challenges that I would have faces using Kali. This is the primary intended route for Helpline, using Windows to connect to the host. Up to this point, my recon has provided credentials for
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Sizzle

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I loved Sizzle. It was just a really tough box that reinforced Windows concepts that I hear about from pentesters in the real world. I'll start with some SMB access, use a .scf file to capture a users NetNTLM hash, and crack it to get creds. From there I can create a certificate
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Conversor

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Conversor is a Linux box hosting a Flask web application that converts nmap XML output to HTML using XSLT. I'll find the source code and exploit insecure use of os.path.join to write a Python reverse shell into a cron-executed scripts directory, or alternatively abuse XSLT's exsl
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
