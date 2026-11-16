# Cloud, Container and Supply Chain

> Tree: `red-team/cloud-container-supply-chain` | **32 sub-skills** | Root router: [`../../SKILL.md`](../../SKILL.md)

**Weak-Model Rule:** Pick the **1 best matching** sub-skill below (`flagship` or `core` first unless a variant profile matches exactly), read its `SKILL.md`, and answer directly using its *Strict Output Contract*.

| Sub-skill | Tier | Focus & When to Use |
|---|---|---|
| [`aws-attacks`](aws-attacks/SKILL.md) | **flagship** | Assesses and exploits AWS environments: credential discovery, IAM policy weaknesses, S3 and other storage exposure, role chaining and service-spe |
| [`azure-and-entra-attacks`](azure-and-entra-attacks/SKILL.md) | **core** | Assesses and exploits Azure and Entra ID: token acquisition and refresh, service principal and managed identity abuse, RBAC weaknesses and storag |
| [`ci-cd-and-dependency-attacks`](ci-cd-and-dependency-attacks/SKILL.md) | **core** | Exploits CI/CD and dependency trust: pipeline injection, secret exposure in build logs, dependency confusion, and artifact tampering |
| [`cloud-iam-privilege-escalation`](cloud-iam-privilege-escalation/SKILL.md) | **core** | Finds and exploits cloud IAM escalation paths: overly permissive policies, pass-role and create-policy primitives, trust policy weaknesses and id |
| [`cloud-recon-and-enumeration`](cloud-recon-and-enumeration/SKILL.md) | **core** | Maps a cloud footprint from outside and inside: tenant and account discovery, DNS and certificate correlation, public storage enumeration and ser |
| [`cloud-storage-and-metadata-abuse`](cloud-storage-and-metadata-abuse/SKILL.md) | **core** | Exploits public and misconfigured cloud storage plus instance metadata: anonymous buckets, ACL and policy gaps, signed URL abuse and IMDS credent |
| [`container-escape`](container-escape/SKILL.md) | **core** | Escapes container isolation: privileged containers, dangerous capabilities and mounts, exposed runtime sockets, and kernel-level escapes |
| [`gcp-attacks`](gcp-attacks/SKILL.md) | **core** | Assesses and exploits GCP: service account key exposure, IAM binding weaknesses, Cloud Storage exposure and metadata service abuse |
| [`github-actions-and-oidc-federation-security`](github-actions-and-oidc-federation-security/SKILL.md) | **core** | Audits GitHub Actions, GitLab CI, and cloud OIDC workload federation (`sts:AssumeRoleWithWebIdentity`): overly broad `sub` claim wildcards (`repo |
| [`kubernetes-pentesting`](kubernetes-pentesting/SKILL.md) | **core** | Assesses Kubernetes clusters: API server exposure, RBAC review, service account token abuse, kubelet and etcd access, and workload escape precond |
| [`saas-oauth-app-and-m365-workspace-security`](saas-oauth-app-and-m365-workspace-security/SKILL.md) | **core** | Assesses enterprise SaaS tenants (Microsoft 365, Google Workspace, Okta, Slack, GitHub Enterprise): over-privileged third-party OAuth app grants, |
| [`secrets-hunting-and-source-leak`](secrets-hunting-and-source-leak/SKILL.md) | **core** | Finds leaked secrets across repositories, CI configs, container images and public sources, then validates them |
| [`supply-chain-attack-recon`](supply-chain-attack-recon/SKILL.md) | **core** | Maps an organization's software supply chain: dependencies, registries, CI providers, maintainers and trust relationships to find reachable attac |
| [`aws-attacks-compute-and-metadata`](aws-attacks-compute-and-metadata/SKILL.md) | **leaf** | AWS compute and metadata exploitation |
| [`aws-attacks-iam-and-role-chaining`](aws-attacks-iam-and-role-chaining/SKILL.md) | **leaf** | AWS IAM and role chaining |
| [`aws-attacks-s3-and-storage`](aws-attacks-s3-and-storage/SKILL.md) | **leaf** | AWS S3 and storage abuse |
| [`azure-and-entra-attacks-rbac-and-managed-identity`](azure-and-entra-attacks-rbac-and-managed-identity/SKILL.md) | **leaf** | Azure RBAC and managed identity abuse |
| [`azure-and-entra-attacks-token-and-consent-abuse`](azure-and-entra-attacks-token-and-consent-abuse/SKILL.md) | **leaf** | Entra token acquisition and consent abuse |
| [`ci-cd-and-dependency-attacks-dependency-confusion`](ci-cd-and-dependency-attacks-dependency-confusion/SKILL.md) | **leaf** | Dependency confusion and typosquatting |
| [`ci-cd-and-dependency-attacks-pipeline-injection`](ci-cd-and-dependency-attacks-pipeline-injection/SKILL.md) | **leaf** | CI/CD pipeline injection |
| [`cloud-persistence-and-defense-evasion`](cloud-persistence-and-defense-evasion/SKILL.md) | **leaf** | Establishes and hides persistence in cloud environments: extra access keys, backdoor roles, trust modifications and audit log gaps |
| [`container-escape-mount-and-socket-escapes`](container-escape-mount-and-socket-escapes/SKILL.md) | **leaf** | Mount and runtime socket escapes |
| [`container-escape-privileged-and-capabilities`](container-escape-privileged-and-capabilities/SKILL.md) | **leaf** | Privileged containers and capability abuse |
| [`ebpf-and-cilium-kubernetes-network-policy-audit`](ebpf-and-cilium-kubernetes-network-policy-audit/SKILL.md) | **leaf** | Reviews Kubernetes NetworkPolicy and Cilium eBPF L3/L4/L7 policies: missing default-deny ingress/egress posture, DNS egress (`kube-dns` UDP/TCP 5 |
| [`infrastructure-as-code-review`](infrastructure-as-code-review/SKILL.md) | **leaf** | Reviews IaC for security defects: Terraform and CloudFormation misconfigurations, overly permissive policies, and drift between declared and actu |
| [`kubernetes-pentesting-admission-and-workload-abuse`](kubernetes-pentesting-admission-and-workload-abuse/SKILL.md) | **leaf** | Admission control and workload abuse |
| [`kubernetes-pentesting-node-and-kubelet-access`](kubernetes-pentesting-node-and-kubelet-access/SKILL.md) | **leaf** | Kubelet and node level access |
| [`kubernetes-pentesting-rbac-and-service-accounts`](kubernetes-pentesting-rbac-and-service-accounts/SKILL.md) | **leaf** | Kubernetes RBAC and service account abuse |
| [`npm-pypi-and-cargo-install-hook-supply-chain`](npm-pypi-and-cargo-install-hook-supply-chain/SKILL.md) | **leaf** | Audits package manager lifecycle execution risks (`npm` `preinstall`/`postinstall`, Python `setup.py` sdist builds, Rust `build.rs` proc-macros): |
| [`oci-container-image-and-registry-supply-chain`](oci-container-image-and-registry-supply-chain/SKILL.md) | **leaf** | Assesses OCI container registries, Cosign/Sigstore image signing, SLSA provenance attestations, multi-stage Dockerfile secret leakage in intermed |
| [`serverless-and-function-abuse`](serverless-and-function-abuse/SKILL.md) | **leaf** | Assesses serverless functions: event injection, over-permissive execution roles, dependency risk, and function URL exposure |
| [`terraform-state-and-gitops-argocd-security`](terraform-state-and-gitops-argocd-security/SKILL.md) | **leaf** | Audits Terraform remote state backends (plaintext secrets in `.tfstate`, state-lock tampering) and GitOps controllers (ArgoCD, Flux): AppProject |
