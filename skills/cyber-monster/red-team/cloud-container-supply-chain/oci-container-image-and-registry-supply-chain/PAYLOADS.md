# Verification Probes and Expected Differentials

> Sub-skill: [`oci-container-image-and-registry-supply-chain`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Reference mutability

```text
# Which deployments use tags rather than digests?
kubectl get pods -A -o json | jq -r '.items[].spec.containers[] | select(.image|contains("@sha256:")|not) | .image' | sort -u
rg -n --no-heading "image:\s*[^@\s]+:[^@\s]+$" -g '*.yaml' -g '*.yml'
```

Expected differential: an empty result means every reference is a digest; any tag reference is the finding, and the list is the remediation scope.

## Class 2 — Signature identity verification

```text
# Bound to a specific builder identity — this is the check that means something.
cosign verify "$IMAGE" \
  --certificate-identity-regexp "https://github.com/acme/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  | jq -r '.[0].optional.Issuer, .[0].critical.identity."docker-reference"'
# The weaker check, for contrast: does any signature exist?
cosign verify "$IMAGE" 2>&1 | head -3
```

Expected differential: the identity-bound check succeeding means the image came from the named workflow; the unbound check succeeding on an image with no identity constraint is the finding.

## Class 3 — Registry access

```text
curl -s -o /dev/null -w 'anon_manifest: %{http_code}\n' "https://$REGISTRY/v2/$REPO/manifests/$TAG"
curl -s -o /dev/null -w 'anon_catalog: %{http_code}\n' "https://$REGISTRY/v2/_catalog"
```

Expected differential: `401` on both is the control; `200` on the manifest means unauthenticated pull, and `200` on the catalog means the repository list is enumerable.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
