# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`nosql-injection`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: NoSQL injection

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** NoSQL injection {{#include ../banners/hacktricks-training.md}} Exploit In PHP you can send an Array changing the sent parameter from _parameter=foo_ to _parameter[arrName]=foo._ The exploits are based in adding an **Operator**: bash username[$ne]=1$password[$ne]=1 #...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: GraphQL NoSQL Injection Through JSON Types

- **Provenance:** Source: `CYBER_CPT/L5/awesome_web_security`
- **Context / Surface:** High-depth analysis (awesome_web_security, edu=4)
- **Root Cause / Analysis:** GraphQL NoSQL Injection Through JSON Types One year ago today, I wrote an article discussing NoSQL Injection and GraphQL. I praised GraphQL for eradicating the entire possibility of NoSQL Injection.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: THM Advent-of-cyber-2021 Day7

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** THM Advent-of-cyber-2021 Day7 Hello everyone :) I am back with the writeup of Tryhackme Advent-of-cyber Day 7. So today we are going to learn about noSQL injection in mongodb and how it works So let's start....
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: [Day 7] Web Exploitation Migration Without Security / Advent of Cyber 3 (2021)

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** [Day 7] Web Exploitation Migration Without Security / Advent of Cyber 3 (2021) Today we will learn about NoSql Injection, as you know this is my first time of NoSql Injection, so I was learning a lot from tryhackme. let's inject into NoSql.... 1\. Interact with the MongoDB server to find the flag.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: TryHackMe / NoSQL Injection / WriteUp

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe / NoSQL Injection / WriteUp A walkthrough depicting basic NoSQL injections on MongoDB. Task 1 Introduction In this room, you will learn about NoSQL Injection. While SQL-based databases are a popular choice for data storage of web applications, several database options that are not based on SQL also exist.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: NoSQL Injection / TryHackMe Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** NoSQL Injection / TryHackMe Walkthrough TASK 2: What is NoSQL Alright, before we dive into NoSQL injection, let’s take a quick (and hopefully fun) peek at how NoSQL databases work, with MongoDB as our star.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: HTB-Mailroom

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HTB-Mailroom Overview: Today, i am going to write a walkthrough of the box: Mailroom. For the user part, we can use xss to do some ssrf stuff with blind nosql injection to extract tristan’s password.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: MongoDB Injection — ASISCTF 2018 Quals — Personal Website Write-Up (WEB Task)

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** MongoDB Injection — ASISCTF 2018 Quals — Personal Website Write-Up (WEB Task) The participants were given following question. > Description: > > I’m so happy because I’ve set up new personal website.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.
