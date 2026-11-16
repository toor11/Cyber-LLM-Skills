# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`container-escape-mount-and-socket-escapes`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: 挂载 docker.sock 导致容器逃逸

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # 挂载 docker.sock 导致容器逃逸 ## 漏洞描述 Docker Socket 是 Docker 守护进程监听的 Unix 域套接字，用来与守护进程通信——查询信息或下发命令。如果在攻击者可控的容器内挂载了该套接字文件（/var/run/docker.sock），可通过 Docker Socket 与 Docker 守护进程通信，发送命令创建并运行一个新的容器，将宿主机的根目录挂载到新创建的容器内部，完成简单逃逸。 ## 环境搭建 基础环境准备（Docker + Minikube + Kubernetes），可参考 [Kubernetes +
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Docker Socket Escape

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # 挂载 Docker Socket 逃逸 Docker Socket 用来与守护进程通信即查询信息或者下发命令。 ## 搭建 创建一个容器并挂载 /var/run/docker/sock 文件 'bash docker run -itd --name with_docker_sock -v /var/run/docker.sock:/var/run/docker.sock ubuntu ' 在容器内安装 Docker 命令行客户端 'bash docker exec -it with_docker_sock /bin/bash apt-ge
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Container With A hostPath Mount Created

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-269`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Container With A hostPath Mount Created - **Date**: 2024-03-26 - **Category**: Application ## Rule 'yaml title: Container With A hostPath Mount Created id: 402b955c-8fe0-4a8c-b635-622b4ac5f902 status: test description: / Detects creation of a container with a hostPath mount.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: cilium-agent container can access the host via 'hostPath' mount

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-269`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact An attacker with access to a Cilium agent pod can write to '/opt/cni/bin' due to a 'hostPath' mount of that directory in the agent pod. By replacing the CNI binary with their own malicious binary and waiting for the creation of a new pod on the node, the attacker can g
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Onedev is an open source, self-hosted Git Server with CI/CD and Kanban. When using Docker-based job

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-269`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Onedev is an open source, self-hosted Git Server with CI/CD and Kanban. When using Docker-based job executors, the Docker socket (e.g. /var/run/docker.sock on Linux) is mounted into each Docker step. - **CVE**: CVE-2022-39206 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: cilium-agent container can access the host via 'hostPath' mount

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-269`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # cilium-agent container can access the host via 'hostPath' mount cilium-agent container can access the host via 'hostPath' mount - **OSV ID**: GHSA-4hc4-pgfx-3mrx - **CVE**: CVE-2023-27593 - **CVSS**: CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H - **Published**: 2023-03-17T18:20
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
