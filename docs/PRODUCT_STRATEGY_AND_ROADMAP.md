# UnoSecur PID product strategy and roadmap

## Product position

UnoSecur PID is the privilege-combination intelligence layer for the UnoSecur
platform. It determines when individually legitimate entitlements combine into
a dangerous capability, preserves the evidence that supports the decision, and
identifies the smallest safe change that breaks the combination.

> **Market message:** UnoSecur PID turns fragmented permissions into explainable
> privilege risk—and shows the safest action to break the path.

PID complements, rather than replaces, identity governance, cloud posture,
SIEM, and incident-management systems. Those systems identify identities,
permissions, configuration weaknesses, and activity. PID answers a different
question:

> What can this human or Non-Human Identity accomplish when its effective
> privileges are combined across systems?

## Why this matters now

Modern organizations grant access through cloud roles, SaaS groups, CI/CD
workloads, Kubernetes service accounts, workload identity federation, API
tokens, and temporary delegation. A single identity can therefore acquire a
dangerous capability without holding an obviously privileged role.

The threat is amplified by:

- Rapid growth in Non-Human Identities and autonomous agents.
- Cross-cloud and cross-SaaS privilege paths.
- Machine-speed credential and token abuse.
- Long-lived inherited access and entitlement drift.
- Software-supply-chain paths joining source control, pipelines, cloud, and
  production workloads.
- Audit and evidence controls administered by the same identities that can
  modify protected systems.

PID makes these compound capabilities visible before they are used for fraud,
privilege escalation, data exfiltration, audit tampering, destructive key
operations, or persistent control-plane access.

## Enterprise operating modes

| Mode                 | Corporate workflow                                       | PID outcome                                                        |
| -------------------- | -------------------------------------------------------- | ------------------------------------------------------------------ |
| Continuous posture   | Scheduled and event-driven entitlement evaluation        | Prioritized toxic combinations with identity, rule, and evidence   |
| Change assurance     | Pre-merge, IaC, role-request, and access-approval checks | Blocks or flags a proposed change that creates a new conflict      |
| Investigation        | IAM, SOC, and cloud-security triage                      | Reconstructs the effective-access path and affected resources      |
| Remediation planning | Access review and least-privilege design                 | Compares safe change options without modifying live access         |
| Governance and audit | SoD review, control testing, and evidence collection     | Reproducible rule decisions, mappings, ownership, and history      |
| Executive oversight  | CISO, CIO, and risk-committee reporting                  | Shows posture trend, remediation efficiency, and residual exposure |

## Corporate stakeholders and decisions

| Stakeholder                     | Decision supported                                                                     |
| ------------------------------- | -------------------------------------------------------------------------------------- |
| CISO and security leadership    | Where is concentrated privilege risk growing, and is remediation reducing it?          |
| IAM and IGA teams               | Which role, group, or permission should be changed to restore separation of duties?    |
| Cloud security                  | Which cross-account, workload, and control-plane combinations create escalation paths? |
| SOC and incident response       | What could a compromised identity reach, and which path should be contained first?     |
| Platform and DevSecOps          | Will a proposed policy, pipeline, or workload change introduce a toxic combination?    |
| Audit and compliance            | Which deterministic rule matched, what evidence supports it, and when was it resolved? |
| Application and business owners | Which remediation preserves required business access with the least disruption?        |

## Threat and abuse coverage

PID rule packs and graph reasoning should cover:

- **Fraud and SoD failure:** create and approve, initiate and release, or
  administer and attest.
- **Privilege escalation:** policy modification, role delegation, impersonation,
  bind/escalate rights, credential creation, and administrative consent.
- **Audit tampering:** protected-system write access combined with the ability to
  disable, alter, or delete audit evidence.
- **Data exfiltration:** sensitive read access combined with export, external
  sharing, snapshot, replication, or egress control.
- **Key and secret abuse:** create, use, rotate, disable, or delete keys and
  secrets without independent oversight.
- **Software-supply-chain compromise:** repository or workflow control combined
  with deployment identity, cloud role, secret, and production access.
- **NHI compromise:** excessive agent, workload, service-account, and automation
  privileges with unattended execution.
- **Cross-platform control:** combinations spanning identity providers, cloud,
  source control, Kubernetes, secret stores, and data platforms.
- **Standing and dormant privilege:** powerful access retained beyond legitimate
  use, including stale credentials and orphaned machine identities.

## Standards and control alignment

PID provides control evidence and mappings; it does not claim certification.
Rule packs should maintain traceable alignment to:

| Framework          | PID contribution                                                                         |
| ------------------ | ---------------------------------------------------------------------------------------- |
| NIST CSF 2.0       | Govern, Identify, Protect, Detect, and Respond evidence for privilege risk               |
| NIST SP 800-53     | AC-5 separation of duties, AC-6 least privilege, and relevant AU audit controls          |
| CIS Controls       | Account management, access control management, audit-log management, and data protection |
| ISO/IEC 27001:2022 | Access control, identity management, privileged access, logging, and monitoring evidence |
| SOC 2              | Logical access and security-monitoring evidence supporting CC6 and CC7 control families  |
| SOX                | Finance and administration separation-of-duties evidence and remediation history         |
| PCI DSS 4.0        | Need-to-know access, privileged-account governance, and audit-log protection             |
| MITRE ATT&CK       | Technique mappings that connect privilege combinations to credible attack behavior       |

## Unique selling proposition

### Evidence-first combination intelligence

PID findings come from deterministic, versioned rules and effective entitlement
evidence. AI explains the decision but does not invent the finding, severity, or
permissions.

### Human and NHI coverage

The same model evaluates employees, contractors, service accounts, workloads,
automation, and agent identities. NHI activity is presented as risky actions
and reachable resources, not merely as account inventory.

### Cross-platform reasoning

PID evaluates one business capability across identity, cloud, SaaS, source
control, Kubernetes, secrets, and data rather than stopping at provider
boundaries.

### Safe remediation intelligence

The what-if engine previews the control change, toxic combinations resolved,
remaining conflicts, and unrelated grants retained. Future optimization will
rank alternative changes by risk reduction and business disruption.

### Native UnoSecur value addition

PID consumes canonical identities, normalized events, scoring, findings, and
existing attack-path capabilities from the appropriate UnoSecur services. It
adds entitlement-combination decisions and remediation simulation without
duplicating those systems of record.

### Measurable business outcomes

Executive reporting connects technical evidence to:

- Toxic identities reduced.
- Conflicts resolved and newly introduced.
- Dangerous changes prevented before deployment.
- Mean time to investigate and remediate.
- Percentage of business access preserved during remediation.
- Human and NHI coverage across connected platforms.
- Accepted-risk aging and control exceptions.

## Market differentiation

| Product category       | Usually answers                                 | PID value addition                                                           |
| ---------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------- |
| IGA and access review  | Who has which role or entitlement?              | Which combinations create an abuse capability and which grant breaks it?     |
| CSPM/CNAPP             | Which cloud configuration is weak?              | Which identity can combine access across cloud and non-cloud control planes? |
| SIEM/XDR               | What suspicious activity occurred?              | Which dangerous capability existed before activity occurred?                 |
| PAM                    | How is privileged access brokered and recorded? | Which standing, inherited, or cross-platform entitlements remain toxic?      |
| Static policy analysis | Is one policy broad or malformed?               | Does effective access across multiple policies and systems form a conflict?  |

## Delivery roadmap

### Phase 1 — Explainable privilege-combination detection

- Deterministic multi-platform rule catalogue.
- User and NHI evaluation.
- Identity, permission, resource, and rule evidence.
- Severity, business narrative, and standards mappings.
- Interactive investigation, trend reporting, and non-destructive simulation.

### Phase 2 — Governed rule and SoD management

- Visual customer rule authoring, evidence testing, draft storage, and
  publication are available in the current product.
- Add maker-checker approval, retirement, rollback, and delegated rule ownership.
- Visual SoD matrix by business process, role, and permission pair.
- Rule ownership, approval, versioning, test fixtures, and effective dates.
- Policy-pack import/export and organization-specific exceptions.

### Phase 3 — Production data adapters and continuous evaluation

- Current prototype: common real-time coverage contract, connector health and
  readiness cards, platform evidence counts, and live entitlement activity feed.
- Uno Entities, Events, Scoring, and Detect adapters.
- AWS, Azure, GCP, Kubernetes, GitHub, Entra, Vault, and SaaS normalization.
- Incremental entitlement updates rather than full rescans.
- Connector health, coverage, freshness, and evidence-quality indicators.

### Phase 4 — Privilege drift and historical evidence

- First-acquired and last-used entitlement history.
- The exact event that completed a toxic combination.
- Role, group, policy, and NHI credential drift.
- Accepted-risk aging and remediation SLA tracking.

### Phase 5 — Advanced graph and NHI intelligence

- Neo4j-backed effective-access and alternative-path resolution.
- Nested group, delegated, impersonated, federated, and cross-account access.
- Shared control points, blast-radius context, and minimum cut-set analysis.
- Agent and workload identity lineage, action scope, credential chain, and owner.

### Phase 6 — Remediation orchestration

- Minimum-change remediation optimizer.
- Side-by-side role, group, policy, permission-boundary, and JIT simulations.
- Human approval with Jira, ServiceNow, and access-governance workflows.
- Guardrailed Terraform, IAM, and RBAC change proposals with rollback evidence.

### Phase 7 — Enterprise governance

- Tenant and business-unit boundaries, RBAC, ABAC, and delegated administration.
- Executive, audit, SoD, and control-evidence reports.
- Exception workflows, compensating controls, attestations, and immutable history.
- Data retention, regional controls, and organization-specific rule packs.

### Phase 8 — Production scale and ecosystem

- High availability, workload isolation, observability, and performance targets.
- Event streaming, distributed evaluation, caching, and large-graph optimization.
- Public APIs, SDKs, webhooks, marketplace rule packs, and integration ecosystem.
- Continuous security testing, threat modeling, recovery, and operational runbooks.

## Product guardrails

- Deterministic evidence establishes every conflict.
- Rule severity is versioned and reviewable.
- AI explanations remain grounded in supplied evidence.
- Simulations are read-only until an authorized human approves a workflow.
- Existing UnoSecur systems remain authoritative for identities, scores,
  findings, events, and incidents.
- Compliance mappings describe control alignment, not guaranteed compliance.
