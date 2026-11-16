# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`frida-diagnostic-tracing-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Trace That Fires Before Any User Action

- **Surface & Preconditions:** An analyst hooks a token verify function and sees calls at launch, concluding the app validates tokens unprompted.
- **Root Cause & Impact:** The launch-time calls are the library's own self-test path, and the conclusion misattributes library behaviour to the feature.
- **Verification & Fix:** Trigger one user action at a time, timestamp each trace line, and keep only records that fall inside the action window.

## Case 2: Return-Value Rewrite Mistaken for Bypass Proof

- **Surface & Preconditions:** A script replaces the verify return with true and the UI opens, presented as an authentication bypass.
- **Root Cause & Impact:** The bypass exists only inside the instrumented process and does not demonstrate a server-side weakness.
- **Verification & Fix:** Restore read-only hooks, confirm what the client sends to the server, and test the server's own decision separately.
