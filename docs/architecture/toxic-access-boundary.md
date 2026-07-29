# Toxic Access Intelligence ownership boundary

## Purpose

Toxic Access Intelligence detects dangerous combinations of effective
entitlements before those entitlements are used in an attack. It complements
the existing UnoSecur platform and must not become a competing source of risk
scores, identities, event detections, or incident state.

## Ownership

| Capability | System of record |
| --- | --- |
| Canonical identities and integrations | Uno Entities |
| Normalized provider activity | Uno Events |
| Risk, policy, blast, bands, and investigation priority | Uno Scoring |
| Findings, evidence, incidents, lifecycle, and deduplication | Uno Detect |
| AWS privilege-escalation paths | Existing anomaly pathfinding detector |
| AI-agent inventory and permissions | Agents service |
| Entitlement conflicts and segregation of duties | Toxic Access Intelligence |
| Cross-platform combination evaluation | Toxic Access Intelligence |
| What-if conflict simulation | Toxic Access Intelligence |
| Minimum-change remediation optimization | Toxic Access Intelligence |

## Ports and adapters

The domain depends on `IdentityAccessSource`, not Prisma or a provider SDK.
`DemoPrismaIdentityAccessSource` exists only for the hackathon dataset. A
production adapter will translate canonical UnoSecur identity and effective
entitlement responses into `IdentityAccessSnapshot`.

The engine does not calculate a risk score. It returns deterministic conflicts,
the matched entitlements, their resources, and their inheritance paths.
Presentation layers can combine those conflicts with scores supplied by Uno
Scoring and findings supplied by Uno Detect.

## AI boundary

Copilot may summarize deterministic evidence and propose remediation. It must
not create permissions, findings, severity, or risk scores. Every generated
statement must be traceable to supplied evidence, and future write operations
must pass through guardrails and human approval.
