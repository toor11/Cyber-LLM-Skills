# Web and Application

> Tree: `red-team/web-and-application` | **184 sub-skills** | Root router: [`../../SKILL.md`](../../SKILL.md)

**Weak-Model Rule:** Pick the **1 best matching** sub-skill below (`flagship` or `core` first unless a variant profile matches exactly), read its `SKILL.md`, and answer directly using its *Strict Output Contract*.

| Sub-skill | Tier | Focus & When to Use |
|---|---|---|
| [`authorization-and-idor`](authorization-and-idor/SKILL.md) | **flagship** | Finds broken object and function level authorization: IDOR across identifiers and verbs, horizontal and vertical privilege escalation, BOLA in AP |
| [`cross-site-scripting`](cross-site-scripting/SKILL.md) | **flagship** | Finds and exploits cross-site scripting in reflected, stored, DOM and mutation contexts, including filter and CSP bypass, framework-specific sink |
| [`sql-injection`](sql-injection/SKILL.md) | **flagship** | Tests and exploits SQL injection across every variant: boolean and time-based blind, UNION and error-based extraction, stacked queries, out-of-ba |
| [`ssrf`](ssrf/SKILL.md) | **flagship** | Exploits server-side request forgery against internal services, cloud metadata endpoints, gopher and file handlers, and DNS rebinding, including |
| [`api-key-and-secret-exposure`](api-key-and-secret-exposure/SKILL.md) | **core** | Finds and validates exposed API keys and secrets in JavaScript bundles, mobile apps, public repositories, error pages and misconfigured storage, |
| [`authentication-bypass`](authentication-bypass/SKILL.md) | **core** | Defeats authentication through logic flaws, forced browsing, response manipulation, alternate paths, JWT and header trust, and default or weak cr |
| [`bug-bounty-and-vdp-workflow`](bug-bounty-and-vdp-workflow/SKILL.md) | **core** | Runs a disciplined bug bounty engagement: scope triage, target prioritization, methodology selection, duplicate avoidance, impact-first reporting |
| [`business-logic-flaws`](business-logic-flaws/SKILL.md) | **core** | Exploits flawed application rules: negative quantities and price manipulation, coupon and discount abuse, workflow and state-machine bypass, curr |
| [`client-side-security-bypasses`](client-side-security-bypasses/SKILL.md) | **core** | Bypasses client-side controls: JavaScript validation, disabled inputs and hidden fields, client-side authorization and routing guards, localStora |
| [`cms-and-framework-exploitation`](cms-and-framework-exploitation/SKILL.md) | **core** | Exploits CMS and web framework platforms: WordPress, Drupal, Joomla, Laravel, Spring, Django, Rails, Next.js, ASP.NET and their plugin and miscon |
| [`csrf`](csrf/SKILL.md) | **core** | Tests cross-site request forgery including missing or weak anti-CSRF tokens, SameSite misconfiguration, JSON and multipart edge cases, login CSRF |
| [`enterprise-appliance-and-n-day-exploitation`](enterprise-appliance-and-n-day-exploitation/SKILL.md) | **core** | Drives n-day exploitation of enterprise appliances and edge devices: fingerprinting, patch diffing to locate the fix, adapting public PoCs, and c |
| [`file-upload-and-webshell`](file-upload-and-webshell/SKILL.md) | **core** | Bypasses file upload validation to achieve web shell execution: extension and MIME tricks, magic-byte spoofing, content-type confusion, filename |
| [`graphql-security`](graphql-security/SKILL.md) | **core** | Tests GraphQL APIs: introspection exposure, resolver-level authorization gaps, batching and alias abuse for brute force, nested query DoS, inject |
| [`http-request-smuggling`](http-request-smuggling/SKILL.md) | **core** | Exploits disagreements between front-end and back-end HTTP parsers: CL.TE, TE.CL, TE.TE, TE.0 and H2.CL desync, including client-side desync and |
| [`injection-detection-methodology`](injection-detection-methodology/SKILL.md) | **core** | Provides a systematic method for discovering injection points anywhere input is interpreted: parameter mining, boundary probing, arithmetic and b |
| [`insecure-deserialization`](insecure-deserialization/SKILL.md) | **core** | Exploits insecure deserialization in Java, PHP, Python, .NET, Ruby and Node gadgets, covering gadget-chain discovery, ysoserial and phpggc payloa |
| [`jwt-attacks`](jwt-attacks/SKILL.md) | **core** | Exploits JSON Web Tokens: algorithm confusion and none, weak HMAC secret cracking, key confusion and injection, claim tampering, kid and jku abus |
| [`nosql-injection`](nosql-injection/SKILL.md) | **core** | Exploits NoSQL injection in MongoDB, CouchDB, Redis and Elasticsearch: operator injection through JSON and query strings, authentication bypass w |
| [`oast-and-blind-vulnerability-testing`](oast-and-blind-vulnerability-testing/SKILL.md) | **core** | Confirms out-of-band and blind vulnerabilities using DNS and HTTP callbacks, timing differentials and stored-trigger techniques |
| [`oauth-oidc-misconfiguration`](oauth-oidc-misconfiguration/SKILL.md) | **core** | Exploits OAuth 2.0 and OpenID Connect flows: redirect URI matching flaws, missing state, code and token leakage, PKCE downgrade, scope escalation |
| [`os-command-injection`](os-command-injection/SKILL.md) | **core** | Exploits operating-system command injection through shell metacharacters, argument injection, blind and time-based confirmation, and escalation t |
| [`path-traversal-and-lfi`](path-traversal-and-lfi/SKILL.md) | **core** | Exploits path traversal and local file inclusion with encoding and normalization bypasses, PHP wrappers, log poisoning, and LFI-to-RCE chains |
| [`pdf-and-headless-renderer-injection`](pdf-and-headless-renderer-injection/SKILL.md) | **core** | Audits server-side HTML-to-PDF and headless screenshot renderers (wkhtmltopdf, Puppeteer, Playwright, WeasyPrint, PrinceXML) for local file read |
| [`prototype-pollution`](prototype-pollution/SKILL.md) | **core** | Exploits JavaScript prototype pollution in Node and browser contexts, from merge and clone sinks to gadget chains that reach RCE or DOM XSS |
| [`race-conditions-and-concurrency`](race-conditions-and-concurrency/SKILL.md) | **core** | Exploits time-of-check to time-of-use and concurrency flaws with single-packet attacks, parallel request bursts, partial-construction windows and |
| [`rest-and-grpc-api-security`](rest-and-grpc-api-security/SKILL.md) | **core** | Tests REST and gRPC APIs for broken object properties, mass assignment, excessive data exposure, HTTP verb and method override abuse, hidden fiel |
| [`saml-assertion-attacks`](saml-assertion-attacks/SKILL.md) | **core** | Exploits SAML SSO: XML signature wrapping, assertion replay, comment and namespace confusion, weak or absent signature validation, and XSW varian |
| [`ssti`](ssti/SKILL.md) | **core** | Exploits server-side template injection across Jinja2, Twig, Freemarker, Velocity, Smarty, Pebble and ERB, from detection polyglots to sandbox es |
| [`waf-bypass-and-payload-obfuscation`](waf-bypass-and-payload-obfuscation/SKILL.md) | **core** | Bypasses web application firewalls and input filters with encoding layers, comment and whitespace tricks, case and keyword splitting, polyglots, |
| [`web-cache-poisoning-and-deception`](web-cache-poisoning-and-deception/SKILL.md) | **core** | Exploits cache key confusion to store malicious responses or leak private data: unkeyed header and parameter poisoning, cache deception via path |
| [`web-pentest-engagement-workflow`](web-pentest-engagement-workflow/SKILL.md) | **core** | Structures a web application penetration test end to end: scoping, rules of engagement, coverage tracking, evidence capture, risk rating and deli |
| [`web-recon-and-content-discovery`](web-recon-and-content-discovery/SKILL.md) | **core** | Maps a web application's surface: directory and file brute forcing, virtual host discovery, parameter mining, JavaScript endpoint extraction, sou |
| [`xxe`](xxe/SKILL.md) | **core** | Exploits XML external entity injection for file disclosure, SSRF, error-based exfiltration and denial of service, including OOXML, SOAP, SAML and |
| [`authentication-bypass-default-and-weak-credentials`](authentication-bypass-default-and-weak-credentials/SKILL.md) | **leaf** | Default and weak credential exploitation |
| [`authentication-bypass-forced-browsing`](authentication-bypass-forced-browsing/SKILL.md) | **leaf** | Authentication bypass through forced browsing and path tricks |
| [`authentication-bypass-header-and-proxy-trust`](authentication-bypass-header-and-proxy-trust/SKILL.md) | **leaf** | Authentication bypass through header and proxy trust |
| [`authentication-bypass-response-manipulation`](authentication-bypass-response-manipulation/SKILL.md) | **leaf** | Authentication bypass through response manipulation |
| [`authorization-and-idor-function-level`](authorization-and-idor-function-level/SKILL.md) | **leaf** | Broken function level authorization |
| [`authorization-and-idor-object-level`](authorization-and-idor-object-level/SKILL.md) | **leaf** | IDOR at the object level |
| [`authorization-and-idor-property-level`](authorization-and-idor-property-level/SKILL.md) | **leaf** | Mass assignment and property level authorization |
| [`authorization-and-idor-tenant-isolation`](authorization-and-idor-tenant-isolation/SKILL.md) | **leaf** | Multi-tenant isolation failures |
| [`business-logic-flaws-payment-and-pricing`](business-logic-flaws-payment-and-pricing/SKILL.md) | **leaf** | Payment and pricing logic flaws |
| [`business-logic-flaws-quota-and-rate`](business-logic-flaws-quota-and-rate/SKILL.md) | **leaf** | Quota, limit and rate logic abuse |
| [`business-logic-flaws-workflow-and-state`](business-logic-flaws-workflow-and-state/SKILL.md) | **leaf** | Workflow and state machine bypass |
| [`clickjacking-and-ui-redressing`](clickjacking-and-ui-redressing/SKILL.md) | **leaf** | Tests framing protections and UI redressing: missing X-Frame-Options and frame-ancestors, double and triple framing, drag-and-drop and cursorjack |
| [`client-side-storage-and-token-theft`](client-side-storage-and-token-theft/SKILL.md) | **leaf** | Exploits tokens and sensitive data stored client-side in localStorage, sessionStorage, IndexedDB and non-HttpOnly cookies, and chains them with X |
| [`cms-and-framework-exploitation-node-and-nextjs`](cms-and-framework-exploitation-node-and-nextjs/SKILL.md) | **leaf** | Node and Next.js framework exploitation |
| [`cms-and-framework-exploitation-php-and-laravel`](cms-and-framework-exploitation-php-and-laravel/SKILL.md) | **leaf** | PHP and Laravel framework exploitation |
| [`cms-and-framework-exploitation-spring-and-java-frameworks`](cms-and-framework-exploitation-spring-and-java-frameworks/SKILL.md) | **leaf** | Spring and Java framework exploitation |
| [`cms-and-framework-exploitation-wordpress`](cms-and-framework-exploitation-wordpress/SKILL.md) | **leaf** | WordPress exploitation |
| [`code-injection-and-eval`](code-injection-and-eval/SKILL.md) | **leaf** | Exploits dynamic code evaluation through eval, assert, preg_replace /e, create_function, script engines and expression evaluators |
| [`code-injection-and-eval-dynamic-language-eval`](code-injection-and-eval-dynamic-language-eval/SKILL.md) | **leaf** | Dynamic language eval injection |
| [`code-injection-and-eval-expression-language`](code-injection-and-eval-expression-language/SKILL.md) | **leaf** | Expression language injection |
| [`cors-misconfiguration`](cors-misconfiguration/SKILL.md) | **leaf** | Exploits cross-origin resource sharing misconfigurations: reflected origins, null origin, wildcard with credentials, subdomain trust, and pre-fli |
| [`cors-misconfiguration-credentialed-wildcard`](cors-misconfiguration-credentialed-wildcard/SKILL.md) | **leaf** | CORS credentialed and wildcard flaws |
| [`cors-misconfiguration-reflected-origin`](cors-misconfiguration-reflected-origin/SKILL.md) | **leaf** | CORS reflected and null origin abuse |
| [`crlf-and-header-injection`](crlf-and-header-injection/SKILL.md) | **leaf** | Injects carriage-return and line-feed sequences to split HTTP messages, poison headers, inject response bodies, and reach cache and log poisoning |
| [`cross-site-scripting-blind-and-oob-xss`](cross-site-scripting-blind-and-oob-xss/SKILL.md) | **leaf** | Blind and out-of-band cross-site scripting |
| [`cross-site-scripting-csp-bypass`](cross-site-scripting-csp-bypass/SKILL.md) | **leaf** | XSS under Content Security Policy |
| [`cross-site-scripting-dom`](cross-site-scripting-dom/SKILL.md) | **leaf** | DOM-based cross-site scripting |
| [`cross-site-scripting-filter-and-context-bypass`](cross-site-scripting-filter-and-context-bypass/SKILL.md) | **leaf** | XSS filter and context bypass |
| [`cross-site-scripting-mutation`](cross-site-scripting-mutation/SKILL.md) | **leaf** | Mutation XSS via parser differentials |
| [`cross-site-scripting-reflected`](cross-site-scripting-reflected/SKILL.md) | **leaf** | Reflected cross-site scripting |
| [`cross-site-scripting-stored`](cross-site-scripting-stored/SKILL.md) | **leaf** | Stored cross-site scripting |
| [`csp-and-security-header-bypass`](csp-and-security-header-bypass/SKILL.md) | **leaf** | Bypasses Content Security Policy and related browser security headers through JSONP endpoints, unsafe-inline gaps, nonce reuse, base-uri and obje |
| [`csv-formula-injection`](csv-formula-injection/SKILL.md) | **leaf** | Injects spreadsheet formulas into exported CSV and XLSX files to achieve command execution or data exfiltration when an analyst opens the file |
| [`cve-poc-research-and-triage`](cve-poc-research-and-triage/SKILL.md) | **leaf** | Finds, evaluates and adapts public proof-of-concept code for a target CVE, filtering unreliable or malicious repos and verifying exploitability s |
| [`dns-rebinding-attacks`](dns-rebinding-attacks/SKILL.md) | **leaf** | Uses DNS rebinding to bypass same-origin and IP-based allowlists, reaching internal services from a browser or an SSRF sink, including TTL manipu |
| [`dom-based-vulnerabilities`](dom-based-vulnerabilities/SKILL.md) | **leaf** | Finds DOM-based flaws where client-side JavaScript moves attacker input into dangerous sinks: innerHTML, eval, location, postMessage handlers and |
| [`email-header-injection`](email-header-injection/SKILL.md) | **leaf** | Injects SMTP headers through contact forms and mail-sending features to add recipients, change the sender, or smuggle a body, including newline e |
| [`enterprise-appliance-and-n-day-exploitation-edge-network-devices`](enterprise-appliance-and-n-day-exploitation-edge-network-devices/SKILL.md) | **leaf** | Edge network device exploitation |
| [`enterprise-appliance-n-day-mail-collaboration`](enterprise-appliance-n-day-mail-collaboration/SKILL.md) | **leaf** | Mail gateway and collaboration platform exploitation |
| [`enterprise-appliance-n-day-vpn-remote-access`](enterprise-appliance-n-day-vpn-remote-access/SKILL.md) | **leaf** | VPN and remote access appliance exploitation |
| [`file-upload-and-webshell-config-and-htaccess-abuse`](file-upload-and-webshell-config-and-htaccess-abuse/SKILL.md) | **leaf** | Upload configuration file abuse |
| [`file-upload-and-webshell-extension-and-mime-bypass`](file-upload-and-webshell-extension-and-mime-bypass/SKILL.md) | **leaf** | Upload extension and MIME validation bypass |
| [`file-upload-and-webshell-filename-and-path-abuse`](file-upload-and-webshell-filename-and-path-abuse/SKILL.md) | **leaf** | Filename and destination path abuse |
| [`file-upload-and-webshell-polyglot-and-archive`](file-upload-and-webshell-polyglot-and-archive/SKILL.md) | **leaf** | Polyglot and archive upload payloads |
| [`graphql-security-batching-and-dos`](graphql-security-batching-and-dos/SKILL.md) | **leaf** | GraphQL batching abuse and denial of service |
| [`graphql-security-introspection-and-schema`](graphql-security-introspection-and-schema/SKILL.md) | **leaf** | GraphQL introspection and schema analysis |
| [`graphql-security-resolver-authorization`](graphql-security-resolver-authorization/SKILL.md) | **leaf** | GraphQL resolver and field authorization gaps |
| [`http-host-header-attacks`](http-host-header-attacks/SKILL.md) | **leaf** | Exploits trust in the Host and forwarded headers for password-reset poisoning, cache poisoning, routing bypass and SSRF |
| [`http-method-and-verb-attacks`](http-method-and-verb-attacks/SKILL.md) | **leaf** | Exploits HTTP method handling: verb tampering past authorization, method override headers, TRACE and OPTIONS disclosure, and method mismatch betw |
| [`http-parameter-pollution-and-mass-assignment`](http-parameter-pollution-and-mass-assignment/SKILL.md) | **leaf** | Exploits duplicate and nested parameters plus over-permissive model binding to bypass validation, escalate privileges and flip logic |
| [`http-request-smuggling-cl-te-and-te-cl`](http-request-smuggling-cl-te-and-te-cl/SKILL.md) | **leaf** | CL.TE and TE.CL smuggling |
| [`http-request-smuggling-client-side-desync`](http-request-smuggling-client-side-desync/SKILL.md) | **leaf** | Client-side desync |
| [`http-request-smuggling-http2-desync`](http-request-smuggling-http2-desync/SKILL.md) | **leaf** | HTTP/2 desync and request tunnelling |
| [`http-request-smuggling-te-te-and-obfuscation`](http-request-smuggling-te-te-and-obfuscation/SKILL.md) | **leaf** | TE.TE and header obfuscation smuggling |
| [`http2-specific-attacks`](http2-specific-attacks/SKILL.md) | **leaf** | Exploits HTTP/2 specific issues: pseudo-header injection, HPACK and header-size abuse, h2c upgrade misuse, rapid-reset resource exhaustion, and s |
| [`injection-detection-methodology-confirmation-discipline`](injection-detection-methodology-confirmation-discipline/SKILL.md) | **leaf** | Injection confirmation discipline |
| [`injection-detection-methodology-parameter-mining`](injection-detection-methodology-parameter-mining/SKILL.md) | **leaf** | Injection parameter mining |
| [`insecure-deserialization-dotnet-gadgets`](insecure-deserialization-dotnet-gadgets/SKILL.md) | **leaf** | NET deserialization gadget chains |
| [`insecure-deserialization-java-gadgets`](insecure-deserialization-java-gadgets/SKILL.md) | **leaf** | Java deserialization gadget chains |
| [`insecure-deserialization-php-gadgets`](insecure-deserialization-php-gadgets/SKILL.md) | **leaf** | PHP deserialization and POP chains |
| [`insecure-deserialization-python-and-ruby-gadgets`](insecure-deserialization-python-and-ruby-gadgets/SKILL.md) | **leaf** | Python and Ruby deserialization attacks |
| [`jndi-injection`](jndi-injection/SKILL.md) | **leaf** | Exploits JNDI lookups in Java applications and logging frameworks, including Log4Shell-style message lookups and LDAP or RMI remote class loading |
| [`jndi-injection-logging-lookups`](jndi-injection-logging-lookups/SKILL.md) | **leaf** | JNDI injection through logging lookups |
| [`jndi-injection-remote-class-loading`](jndi-injection-remote-class-loading/SKILL.md) | **leaf** | JNDI remote class loading and trust bypass |
| [`jwt-attacks-algorithm-confusion`](jwt-attacks-algorithm-confusion/SKILL.md) | **leaf** | JWT algorithm confusion and none |
| [`jwt-attacks-claim-tampering`](jwt-attacks-claim-tampering/SKILL.md) | **leaf** | JWT claim tampering and lifecycle gaps |
| [`jwt-attacks-header-injection`](jwt-attacks-header-injection/SKILL.md) | **leaf** | JWT header injection abuse |
| [`jwt-attacks-secret-cracking`](jwt-attacks-secret-cracking/SKILL.md) | **leaf** | JWT secret cracking and weak key exploitation |
| [`ldap-and-xpath-injection`](ldap-and-xpath-injection/SKILL.md) | **leaf** | Injects into LDAP filters and XPath queries to bypass authentication and enumerate directory or XML data |
| [`ldap-and-xpath-injection-ldap`](ldap-and-xpath-injection-ldap/SKILL.md) | **leaf** | LDAP injection |
| [`ldap-and-xpath-injection-xpath`](ldap-and-xpath-injection-xpath/SKILL.md) | **leaf** | XPath injection |
| [`mfa-and-otp-bypass`](mfa-and-otp-bypass/SKILL.md) | **leaf** | Bypasses multi-factor and one-time-password controls: missing server-side checks, response manipulation, code reuse and brute force, backup-code |
| [`mobile-and-hybrid-web-api-abuse`](mobile-and-hybrid-web-api-abuse/SKILL.md) | **leaf** | Tests the web APIs behind mobile and hybrid apps where client-side controls are absent: unauthenticated endpoints, hardcoded keys, logic implemen |
| [`oast-and-blind-vulnerability-testing-dns-and-http-callbacks`](oast-and-blind-vulnerability-testing-dns-and-http-callbacks/SKILL.md) | **leaf** | DNS and HTTP callback confirmation |
| [`oast-and-blind-vulnerability-testing-timing-oracles`](oast-and-blind-vulnerability-testing-timing-oracles/SKILL.md) | **leaf** | Timing oracle confirmation |
| [`oauth-oidc-misconfiguration-flow-and-state-flaws`](oauth-oidc-misconfiguration-flow-and-state-flaws/SKILL.md) | **leaf** | OAuth flow and state parameter flaws |
| [`oauth-oidc-misconfiguration-redirect-uri-abuse`](oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) | **leaf** | OAuth redirect URI validation bypass |
| [`oauth-oidc-misconfiguration-token-and-scope-abuse`](oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) | **leaf** | OAuth token and scope abuse |
| [`open-redirect`](open-redirect/SKILL.md) | **leaf** | Exploits unvalidated redirects and forwards for phishing, OAuth token theft and SSRF pivoting, including allowlist and parser-differential bypass |
| [`open-redirect-allowlist-bypass`](open-redirect-allowlist-bypass/SKILL.md) | **leaf** | Open redirect allowlist bypass |
| [`open-redirect-chain-to-token-theft`](open-redirect-chain-to-token-theft/SKILL.md) | **leaf** | Open redirect chaining to token theft |
| [`openapi-and-swagger-exposure`](openapi-and-swagger-exposure/SKILL.md) | **leaf** | Exploits exposed API documentation and schemas to enumerate hidden endpoints, parameters and internal hosts, including swagger-ui, OpenAPI JSON a |
| [`os-command-injection-argument-injection`](os-command-injection-argument-injection/SKILL.md) | **leaf** | Argument injection without shell metacharacters |
| [`os-command-injection-blind-and-time-based`](os-command-injection-blind-and-time-based/SKILL.md) | **leaf** | Blind and time-based command injection |
| [`os-command-injection-escalation-to-shell`](os-command-injection-escalation-to-shell/SKILL.md) | **leaf** | Command injection escalation to interactive shell |
| [`os-command-injection-shell-metacharacter-bypass`](os-command-injection-shell-metacharacter-bypass/SKILL.md) | **leaf** | Shell metacharacter filter bypass |
| [`password-reset-and-account-recovery`](password-reset-and-account-recovery/SKILL.md) | **leaf** | Exploits password reset and account recovery: host header and link poisoning, token prediction and reuse, user enumeration, response leakage, and |
| [`path-traversal-and-lfi-encoding-bypass`](path-traversal-and-lfi-encoding-bypass/SKILL.md) | **leaf** | Traversal encoding and normalization bypass |
| [`path-traversal-and-lfi-lfi-to-rce`](path-traversal-and-lfi-lfi-to-rce/SKILL.md) | **leaf** | LFI to remote code execution chains |
| [`path-traversal-and-lfi-log-and-cache-poisoning`](path-traversal-and-lfi-log-and-cache-poisoning/SKILL.md) | **leaf** | Log and cache poisoning for inclusion |
| [`path-traversal-and-lfi-php-wrappers`](path-traversal-and-lfi-php-wrappers/SKILL.md) | **leaf** | PHP stream wrapper exploitation |
| [`prototype-pollution-client-side-gadgets`](prototype-pollution-client-side-gadgets/SKILL.md) | **leaf** | Client-side prototype pollution gadgets |
| [`prototype-pollution-rce-chains`](prototype-pollution-rce-chains/SKILL.md) | **leaf** | Prototype pollution to remote code execution |
| [`prototype-pollution-server-side`](prototype-pollution-server-side/SKILL.md) | **leaf** | Server-side prototype pollution |
| [`race-conditions-and-concurrency-limit-bypass`](race-conditions-and-concurrency-limit-bypass/SKILL.md) | **leaf** | Race-based limit and balance bypass |
| [`race-conditions-and-concurrency-single-packet-attack`](race-conditions-and-concurrency-single-packet-attack/SKILL.md) | **leaf** | Single-packet and last-byte synchronization attacks |
| [`saml-and-webauthn-passkey-implementation-flaws`](saml-and-webauthn-passkey-implementation-flaws/SKILL.md) | **leaf** | Audits WebAuthn / FIDO2 Passkey relying-party implementations: missing `rpIdHash` or `origin` verification, challenge replay/non-binding, `signCo |
| [`saml-assertion-attacks-assertion-forgery`](saml-assertion-attacks-assertion-forgery/SKILL.md) | **leaf** | SAML assertion forgery and replay |
| [`saml-assertion-attacks-signature-wrapping`](saml-assertion-attacks-signature-wrapping/SKILL.md) | **leaf** | SAML XML signature wrapping |
| [`server-side-includes-injection`](server-side-includes-injection/SKILL.md) | **leaf** | Exploits SSI injection to read files and execute commands where .shtml or SSI-enabled handlers process user input, including echo, exec and inclu |
| [`session-and-token-lifecycle`](session-and-token-lifecycle/SKILL.md) | **leaf** | Tests session handling weaknesses: fixation, predictable identifiers, missing rotation, weak expiry, revocation gaps, cookie attribute mistakes a |
| [`session-and-token-lifecycle-cookie-attribute-flaws`](session-and-token-lifecycle-cookie-attribute-flaws/SKILL.md) | **leaf** | Cookie attribute and scope flaws |
| [`session-and-token-lifecycle-fixation-and-prediction`](session-and-token-lifecycle-fixation-and-prediction/SKILL.md) | **leaf** | Session fixation and identifier prediction |
| [`session-and-token-lifecycle-revocation-gaps`](session-and-token-lifecycle-revocation-gaps/SKILL.md) | **leaf** | Session revocation and logout gaps |
| [`sql-injection-mssql-variants`](sql-injection-mssql-variants/SKILL.md) | **leaf** | Microsoft SQL Server specific SQL injection |
| [`sql-injection-mysql-variants`](sql-injection-mysql-variants/SKILL.md) | **leaf** | MySQL and MariaDB specific SQL injection |
| [`sql-injection-oracle-variants`](sql-injection-oracle-variants/SKILL.md) | **leaf** | Oracle specific SQL injection |
| [`sql-injection-orm-and-query-builder`](sql-injection-orm-and-query-builder/SKILL.md) | **leaf** | SQL injection through ORMs and query builders |
| [`sql-injection-postgres-variants`](sql-injection-postgres-variants/SKILL.md) | **leaf** | PostgreSQL specific SQL injection |
| [`sql-injection-second-order`](sql-injection-second-order/SKILL.md) | **leaf** | Second-order SQL injection |
| [`sql-injection-sqlite-variants`](sql-injection-sqlite-variants/SKILL.md) | **leaf** | SQLite specific SQL injection |
| [`sql-injection-waf-tamper-chains`](sql-injection-waf-tamper-chains/SKILL.md) | **leaf** | SQL injection tamper script chains for WAF bypass |
| [`ssrf-allowlist-bypass`](ssrf-allowlist-bypass/SKILL.md) | **leaf** | SSRF allowlist and filter bypass |
| [`ssrf-blind-ssrf`](ssrf-blind-ssrf/SKILL.md) | **leaf** | Blind SSRF confirmation and exfiltration |
| [`ssrf-cloud-metadata`](ssrf-cloud-metadata/SKILL.md) | **leaf** | SSRF against cloud instance metadata services |
| [`ssrf-internal-service-pivot`](ssrf-internal-service-pivot/SKILL.md) | **leaf** | SSRF to internal service access |
| [`ssrf-protocol-smuggling`](ssrf-protocol-smuggling/SKILL.md) | **leaf** | SSRF through non-HTTP protocol handlers |
| [`ssti-java-template-engines`](ssti-java-template-engines/SKILL.md) | **leaf** | Java template engine injection |
| [`ssti-jinja2-and-twig`](ssti-jinja2-and-twig/SKILL.md) | **leaf** | Jinja2 and Twig template injection |
| [`ssti-node-and-client-engines`](ssti-node-and-client-engines/SKILL.md) | **leaf** | Node and client-side template injection |
| [`ssti-sandbox-escape`](ssti-sandbox-escape/SKILL.md) | **leaf** | Template sandbox escape |
| [`subdomain-takeover`](subdomain-takeover/SKILL.md) | **leaf** | Finds and claims dangling DNS records pointing at deprovisioned SaaS, cloud, CDN and PaaS resources, covering CNAME fingerprints, NS delegation a |
| [`subdomain-takeover-cname-fingerprints`](subdomain-takeover-cname-fingerprints/SKILL.md) | **leaf** | CNAME fingerprint subdomain takeover |
| [`subdomain-takeover-ns-and-service-takeover`](subdomain-takeover-ns-and-service-takeover/SKILL.md) | **leaf** | NS delegation and service level takeover |
| [`type-juggling-and-loose-comparison`](type-juggling-and-loose-comparison/SKILL.md) | **leaf** | Exploits loose type comparison and coercion across PHP, JavaScript and other dynamic languages, including magic hashes, array and string confusio |
| [`type-juggling-javascript-other-languages`](type-juggling-javascript-other-languages/SKILL.md) | **leaf** | Type coercion flaws beyond PHP |
| [`type-juggling-and-loose-comparison-php-juggling`](type-juggling-and-loose-comparison-php-juggling/SKILL.md) | **leaf** | PHP type juggling exploitation |
| [`unicode-normalization-and-charset-confusion`](unicode-normalization-and-charset-confusion/SKILL.md) | **leaf** | Audits Unicode normalization (NFKC/NFKD), case-mapping collisions (Kelvin sign, dotless i), and charset/Jackson hex-cast parser differentials tha |
| [`waf-bypass-and-payload-obfuscation-comment-and-whitespace`](waf-bypass-and-payload-obfuscation-comment-and-whitespace/SKILL.md) | **leaf** | Comment and whitespace obfuscation |
| [`waf-bypass-and-payload-obfuscation-encoding-layers`](waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md) | **leaf** | Encoding layer obfuscation |
| [`waf-bypass-and-payload-obfuscation-parser-differentials`](waf-bypass-and-payload-obfuscation-parser-differentials/SKILL.md) | **leaf** | WAF parser differential exploitation |
| [`waf-bypass-and-payload-obfuscation-rule-specific-evasion`](waf-bypass-and-payload-obfuscation-rule-specific-evasion/SKILL.md) | **leaf** | Rule-specific WAF evasion |
| [`web-app-fuzzing-and-automation`](web-app-fuzzing-and-automation/SKILL.md) | **leaf** | Automates web testing at scale: request templating, payload list management, response diffing, and rate-safe fuzzing with Burp, ffuf, Nuclei and |
| [`web-cache-poisoning-and-deception-cdn-specific-behaviour`](web-cache-poisoning-and-deception-cdn-specific-behaviour/SKILL.md) | **leaf** | CDN-specific cache behaviour exploitation |
| [`web-cache-poisoning-and-deception-deception-and-path`](web-cache-poisoning-and-deception-deception-and-path/SKILL.md) | **leaf** | Cache deception through path confusion |
| [`web-cache-poisoning-and-deception-unkeyed-input`](web-cache-poisoning-and-deception-unkeyed-input/SKILL.md) | **leaf** | Cache poisoning through unkeyed input |
| [`web-fingerprinting-and-tech-detection`](web-fingerprinting-and-tech-detection/SKILL.md) | **leaf** | Identifies server, framework, CMS, language and library versions from headers, cookies, error pages, static assets, favicons and behaviour |
| [`web-recon-and-content-discovery-archive-and-osint-recon`](web-recon-and-content-discovery-archive-and-osint-recon/SKILL.md) | **leaf** | Archive and OSINT web recon |
| [`web-recon-and-content-discovery-directory-and-file`](web-recon-and-content-discovery-directory-and-file/SKILL.md) | **leaf** | Directory and file brute forcing |
| [`web-recon-and-content-discovery-javascript-analysis`](web-recon-and-content-discovery-javascript-analysis/SKILL.md) | **leaf** | JavaScript analysis for endpoints and secrets |
| [`webshell-management-and-interaction`](webshell-management-and-interaction/SKILL.md) | **leaf** | Operates and stabilizes an uploaded web shell: choosing the right interpreter, evading static detection, maintaining access, and pivoting through |
| [`websocket-security`](websocket-security/SKILL.md) | **leaf** | Tests WebSocket endpoints: missing origin checks, cross-site WebSocket hijacking, authorization applied only at handshake, message-level injectio |
| [`xml-attacks-xxe-and-xslt`](xml-attacks-xxe-and-xslt/SKILL.md) | **leaf** | Covers XML parser attacks beyond basic XXE: XSLT injection and extension abuse, XPath injection, schema and DTD attacks, and parser differentials |
| [`xml-attacks-xxe-and-xslt-xpath-and-schema`](xml-attacks-xxe-and-xslt-xpath-and-schema/SKILL.md) | **leaf** | XPath and XML schema attacks |
| [`xml-attacks-xxe-and-xslt-xslt-injection`](xml-attacks-xxe-and-xslt-xslt-injection/SKILL.md) | **leaf** | XSLT injection and extension abuse |
| [`xxe-file-disclosure`](xxe-file-disclosure/SKILL.md) | **leaf** | XXE local file disclosure |
| [`xxe-oob-exfiltration`](xxe-oob-exfiltration/SKILL.md) | **leaf** | Out-of-band XXE exfiltration |
| [`xxe-ooxml-and-svg`](xxe-ooxml-and-svg/SKILL.md) | **leaf** | XXE in OOXML, SVG and document formats |
| [`xxe-parser-differential-bypass`](xxe-parser-differential-bypass/SKILL.md) | **leaf** | XXE parser differential and filter bypass |
| [`zip-slip-and-archive-extraction-attacks`](zip-slip-and-archive-extraction-attacks/SKILL.md) | **leaf** | Audits archive extraction routines (ZIP, TAR, 7z, APK, Helm/OCI layers) for Zip-Slip path traversal, symlink/hardlink escape, decompression bombs |
