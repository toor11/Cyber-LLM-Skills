# Multi-Dataset Provenance Log

> Sub-skill: [`graphql-security`](SKILL.md) | Family: **Web and Application**

Case labels below are stored in this file. The procedure is in [`SKILL.md`](SKILL.md).

## In-file case labels

| Tag | What this file already states |
|---|---|
| - | Graphql introspection is enabled and leaks details about the schema |
| CWE-20 | HTB: Overgraph |
| CWE-20 | HTB: Help |
| CWE-20 | GraphQL NoSQL Injection Through JSON Types |
| CWE-20 | DarkCON Challs |
| CWE-20 | CTF Web - XXE, XML Injection, Command Injection, GraphQL |
| CWE-20 | GraphQL Cheat Sheet |
| GraphQL Introspection | Introspection queries are used to determine the GraphQL schema's efficiency and performance... |
| GraphQL Schema | A list of supported queries such as Query, Mutation, and Subscription types. |
| explain | Follow Black Hat GraphQL’s lab chapter: 1. Use an isolated Kali (or similar) VM |
| explain | Cop audits configuration/DoS posture; CrackQL attacks credentials/arguments with |
| explain | Some servers accept a JSON **array** of query objects in one POST, executing man |
| explain | Combine checklists, hands-on labs (DVGA), and conference talks. Practice tooling |
| explain | graphql { __schema { mutationType { fields { name args { name type { name kind o |
| explain | **Nested Queries** — this technique applies to GraphQL Injection. Use the follow |
| explain | **JSON List Based Batching** — this technique applies to GraphQL Injection. Use |
| explain | Overview Discover OpenAPI/Swagger, GraphQL introspection, mobile app traffic, an |
| identify | **Identify An Injection Point** — this technique applies to GraphQL Injection. U |
| identify | '__typename' is a meta-field present on almost all types. Query '{ __typename }' |
| identify | POST a JSON array of two trivial '{__typename}' queries. If both results return |
| identify | Send a standard introspection query. If you receive an error like “introspection |
| identify | Send malformed queries and look for stack traces, engine versions, or 'extension |
| identify | - inql - InQL - A Burp Extension for GraphQL Security Testing - GraphQLmap - Gra |
| identify | Tools / Name / Description / / ---- / ----------- / / / / / **GraphQL** / / Batc |
| identify | 1. Check if introspection is enabled: query{__schema{types{name}}}. 2. Use InQL |
| remediate | Overview Discover OpenAPI/Swagger, GraphQL introspection, mobile app traffic, an |
| remediate | **Vulnerability Class:** graphql **CWE:** CWE-284 **Weakness:** Improper Access |
