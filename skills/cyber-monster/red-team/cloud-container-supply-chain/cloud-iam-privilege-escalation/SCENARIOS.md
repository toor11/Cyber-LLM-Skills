# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cloud-iam-privilege-escalation`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: iam:PassRole, codestar:CreateProject

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** iam:PassRole, codestar:CreateProject With these permissions you can **abuse a codestar IAM Role** to perform **arbitrary actions** through a **cloudformation template**. To exploit this you need to create a **S3 bucket that is accessible** from the attacked account.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: GCP - Dataflow Privilege Escalation

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** GCP - Dataflow Privilege Escalation Dataflow 'storage.objects.create', 'storage.objects.get', 'storage.objects.update' Dataflow does not validate integrity of UDFs and job template YAMLs stored in GCS.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: GCP Dataproc Privilege Escalation

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** GCP Dataproc Privilege Escalation Dataproc 'dataproc.clusters.get', 'dataproc.clusters.use', 'dataproc.jobs.create', 'dataproc.jobs.get', 'dataproc.jobs.list', 'storage.objects.create', 'storage.objects.get' I was unable to get a reverse shell using this method, however it is possible to leak SA...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: GCP - Public Buckets Privilege Escalation

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** GCP - Public Buckets Privilege Escalation Buckets Privilege Escalation If the bucket policy allowed either “allUsers” or “allAuthenticatedUsers” to **write to their bucket policy** (the **storage.buckets.setIamPolicy** permission)**,** then anyone can modify the bucket policy and grant himself full...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 5: GCP - Dataflow Privilege Escalation

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # GCP - Dataflow Privilege Escalation ## Dataflow ### 'storage.objects.create', 'storage.objects.get', 'storage.objects.update' Dataflow does not validate integrity of UDFs and job template YAMLs stored in GCS. With bucket write access, you can overwrite these files to inject cod
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: iam:PassRole, cloudformation:CreateStack,and cloudformation:DescribeStacks

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # iam:PassRole, cloudformation:CreateStack, and cloudformation:DescribeStacks An attacker could for example use a **cloudformation template** that generates **keys for an admin** user like: 'json { "Resources": { "AdminUser": { "Type": "AWS::IAM::User" }, "AdminPolicy": { "Type
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: iam:PassRole, codestar:CreateProject

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # iam:PassRole, codestar:CreateProject With these permissions you can **abuse a codestar IAM Role** to perform **arbitrary actions** through a **cloudformation template**. To exploit this you need to create a **S3 bucket that is accessible** from the attacked account. Upload a fi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: GCP Dataproc Privilege Escalation

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # GCP Dataproc Privilege Escalation ## Dataproc ### 'dataproc.clusters.get', 'dataproc.clusters.use', 'dataproc.jobs.create', 'dataproc.jobs.get', 'dataproc.jobs.list', 'storage.objects.create', 'storage.objects.get' I was unable to get a reverse shell using this method, however
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
