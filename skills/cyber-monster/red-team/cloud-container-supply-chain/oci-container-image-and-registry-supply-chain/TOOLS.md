# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`oci-container-image-and-registry-supply-chain`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `cosign` | `cosign verify IMAGE --certificate-identity X --certificate-oidc-issuer Y` | Whether the signature is bound to the expected builder | Sigstore |
| `cosign` | `cosign verify-attestation --type spdx IMAGE` | Whether an SBOM attestation exists and who made it | Sigstore |
| `crane` | `crane digest IMAGE:TAG` | The digest a tag resolves to now, without pulling layers | go-containerregistry |
| `skopeo` | `skopeo inspect docker://IMAGE` | Manifest and config without a local daemon | skopeo |
| `trivy` | `trivy image --severity HIGH,CRITICAL IMAGE` | Vulnerabilities in the image content | Aqua |
| `syft` | `syft IMAGE -o spdx-json` | SBOM generation, which is the artefact the review asks for | Anchore |

## Minimal script shape

```python
# Report the four links per deployed reference.
import json
import subprocess

def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True).stdout

def links(image: str) -> dict:
    pinned = "@sha256:" in image
    digest = sh("crane", "digest", image).strip() if not pinned else image.split("@")[-1]
    verify = subprocess.run(["cosign", "verify", image,
                             "--certificate-identity-regexp", r"https://github.com/acme/.*",
                             "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"],
                            capture_output=True, text=True)
    return {"image": image, "pinned": pinned, "digest": digest[:19],
            "identity_bound_signature": verify.returncode == 0}

if __name__ == "__main__":
    for img in ("registry.example.com/api:1.4", "registry.example.com/api@sha256:5f2a1c9e"):
        print(links(img))
```

`pinned: False` is the mutability finding and `identity_bound_signature: False` is the verification finding; both are needed for the chain to hold.
