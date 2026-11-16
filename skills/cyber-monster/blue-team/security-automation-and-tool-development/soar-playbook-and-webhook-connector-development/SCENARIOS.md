# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`soar-playbook-and-webhook-connector-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative automation-safety failures, each with the artifact that proves the diagnosis.

## Case 1: A domain controller was isolated by automation

- **Surface & Preconditions:** a playbook isolates any host named in an alert, and the protected-asset check is a comment in the runbook rather than code.
- **Root cause & impact:** one alert naming a DC triggers fleet-wide authentication failure. The response to the alert becomes a larger incident than the alert itself, and the isolation may block the very access needed to investigate.
- **Verification & fix:** enforce the protected list in the receiver against internal inventory, refuse with a recorded reason, and test the refusal path in CI with a `dc01` fixture.

## Case 2: The same host isolated twice

- **Surface & Preconditions:** the calling platform retries a delivery after a timeout, and the receiver has no dedup.
- **Root cause & impact:** the first call succeeded but the response was lost, so the retry executes the action again; the EDR audit log shows two actions, the host's containment record is ambiguous, and the reversal path now needs to handle a count it did not expect.
- **Verification & fix:** require a caller-supplied idempotency key, store the decision before responding, and return the prior decision on a repeat.

## Case 3: A forged webhook started a containment run

- **Surface & Preconditions:** the receiver parses JSON and acts without verifying a signature, relying on the URL being unguessable.
- **Root cause & impact:** anyone who observes the URL (logs, proxies, screenshots) can drive containment. There is no authentication boundary between the internet and the response plane.
- **Verification & fix:** verify an HMAC over the raw body with a rotating shared secret, enforce a timestamp window, and reject reused nonces.

## Case 4: Containment abandoned on a 429

- **Surface & Preconditions:** the EDR API rate-limits during a mass-alert event and returns 429.
- **Root cause & impact:** the connector treats any non-2xx as failure, logs "isolation failed", and stops — exactly when many hosts need action and the API is merely throttling.
- **Verification & fix:** retry 429/5xx/timeouts with exponential backoff and jitter inside a bounded budget, and keep the idempotency key so a retry that follows a successful-but-unacknowledged call is harmless.
