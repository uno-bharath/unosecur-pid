# Multi-cluster Kubernetes integration

## Purpose

PID adds Kubernetes evidence that is not currently available through the
production UnoSecur connector estate. It combines GKE and EKS RBAC/workload
evidence with UnoSecur tenant evidence to detect toxic privileges spanning
cloud, SaaS, CI/CD, secrets, and Kubernetes control planes.

## Local authentication

Use the default kubeconfig and cloud-provider credential helpers. Do not copy
GCP service-account JSON, AWS keys, bearer tokens, or kubeconfig contents into
environment variables.

PID must use an explicit context allowlist. It must never iterate across every
context visible to an administrator.

```dotenv
KUBERNETES_ENABLED=true
KUBERNETES_KUBECONFIG=
KUBERNETES_CONTEXTS=<gke-nonprod-context>,<eks-nonprod-context>
KUBERNETES_WATCH_ENABLED=true
KUBERNETES_ALLOW_PRODUCTION=false
```

An empty `KUBERNETES_KUBECONFIG` uses the standard kubeconfig resolution. Use
an absolute path only when a separate read-only kubeconfig is created for PID.

## Safe rollout

1. Start with the GKE non-production and EKS non-production contexts only.
2. Run metadata-only connectivity checks.
3. Collect RBAC and workload configuration with `get`, `list`, and `watch`.
4. Compare cluster counts with `kubectl` and the existing platform inventory.
5. Run toxic rules in shadow mode.
6. Add production only after a dedicated read-only service account and approval.

## Required read model

- Namespaces and namespace labels.
- ServiceAccounts without reading token Secret contents.
- Roles and ClusterRoles.
- RoleBindings and ClusterRoleBindings.
- Pods, Deployments, StatefulSets, DaemonSets, Jobs, and CronJobs.
- Workload service-account assignments and pod security context.

## Explicitly prohibited permissions

- Reading Secret data.
- Creating service-account tokens.
- Pod execution, attach, or port-forward.
- User or service-account impersonation.
- Creating, updating, patching, or deleting cluster resources.
- Approving certificates or modifying admission policy.

## Detection experience

The Kubernetes Checks view groups evidence into searchable, expandable checks:

- Severity distribution and affected-resource totals.
- Security, reliability, and efficiency categories.
- CIS, NSA/CISA, Pod Security Standards, MITRE ATT&CK, Polaris, and Kubescape mappings.
- Why the combination matters.
- How to break the toxic path safely.
- Affected clusters, namespaces, workloads, containers, identities, and NHIs.
- What-if role, binding, permission, and workload-service-account simulations.

## Initial toxic combinations

- RBAC `bind` plus access to a privileged ClusterRole.
- RBAC `escalate` plus Role or ClusterRole modification.
- `impersonate` plus secrets or workload administration.
- Workload creation plus a privileged ServiceAccount.
- Pod creation plus privileged security context or hostPath mounting.
- Secret metadata access plus pod execution capability.
- Cluster administration plus AWS/GCP/Azure identity federation.
- GitHub or Jenkins deployment control plus Kubernetes administration.
- One NHI privileged across multiple clusters or environments.

## Production authentication

- GKE: Workload Identity Federation for GKE.
- EKS: EKS Pod Identity or IRSA.
- Separate Kubernetes service account and cloud identity per environment.
- Read-only ClusterRole scoped to only the resources required by PID.

Administrator kubeconfig access is acceptable only for initial local discovery.
It must not become the application's production authentication mechanism.
