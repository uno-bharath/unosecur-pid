# UnoSecur PID

**Privilege Intelligence & Detection**

UnoSecur PID identifies dangerous combinations of
effective entitlements before they are exploited. It correlates permissions
across enterprise applications, identity providers, cloud platforms, source
control, Kubernetes, and secret stores; explains how an identity received the
access; and previews the smallest safe remediation without changing live access.

This repository is a hackathon MVP and a proposed value-added capability for
the wider UnoSecur platform.

## Hackathon identity

| Item | Name |
| --- | --- |
| Product | **UnoSecur PID — Privilege Intelligence & Detection** |
| Repository | **unosecur-pid** |
| Team | **Access Sentinels** |
| One-line pitch | Detect dangerous privilege combinations before they become attack paths. |

The product name describes the capability precisely: the platform detects toxic
access combinations rather than labelling people or machine identities as
inherently toxic.

## Why this exists

Access is usually reviewed one permission, role, or platform at a time. That
misses combinations where individually legitimate permissions produce a
dangerous capability together.

Examples include:

- Creating a vendor and approving payments to that vendor.
- Creating an identity and assigning it an administrative role.
- Administering source code, delegating a production cloud role, and
  controlling a Kubernetes cluster.
- Reading CI/CD secrets, assuming a cloud role, and reading production secrets.

Toxic Access Intelligence evaluates the effective access collectively and
answers:

- Which combinations are dangerous?
- Which systems and resources participate in the conflict?
- Was each entitlement direct, inherited, or delegated?
- Which permission removal breaks the conflict?
- How much unrelated access remains after the proposed change?

## Product ownership boundary

The project deliberately does not duplicate existing UnoSecur business logic.

| Capability | System of record |
| --- | --- |
| Canonical identities, NHIs, groups, resources, and integrations | Uno Entities |
| Normalized cloud, identity, SaaS, and DevOps events | Uno Events |
| Risk, policy, blast-radius, bands, and investigation priority | Uno Scoring |
| Findings, incidents, evidence, deduplication, and lifecycle | Uno Detect |
| Existing AWS privilege-escalation pathfinding | UnoSecur anomaly detection |
| AI-agent, tool, and permission inventory | Agents service |
| Entitlement conflicts and segregation of duties | **This project** |
| Cross-platform toxic access combinations | **This project** |
| What-if conflict resolution | **This project** |
| Minimum-change remediation optimization | **This project — roadmap** |

The complete boundary is documented in
[`docs/architecture/toxic-access-boundary.md`](docs/architecture/toxic-access-boundary.md).

## Current MVP

### Toxic Access engine

- Provider-neutral entitlement-combination model.
- Deterministic conflict evaluation.
- Human, service-account, and workload identity support.
- Platform and resource constraints.
- Cross-platform minimum-coverage conditions.
- Evidence containing permission, resource, and effective-access path.
- MITRE ATT&CK and NIST mappings.
- No locally invented production risk score.

### What-if simulation

- Removes proposed permissions from an in-memory snapshot.
- Re-evaluates conflicts without persisting access changes.
- Reports resolved and remaining conflicts.
- Reports how many unrelated grants remain.

### Investigation experience

- UnoSecur-themed dashboard.
- Priority identity queue.
- Severity-filtered entitlement conflicts.
- Interactive effective-access path.
- Floating, animated UnoSecur Copilot.
- Responsive layout and reduced-motion accessibility.

### Local Copilot

- Uses Ollama through its local HTTP API.
- Receives deterministic Toxic Access evidence.
- Explains business impact and remediation.
- Falls back to a deterministic evidence summary if Ollama is unavailable.
- Does not create scores, permissions, findings, or severity.

## Initial conflict catalogue

The MVP includes these unique examples:

| Rule | Purpose |
| --- | --- |
| `TAI-SOD-FIN-001` | Vendor creation and payment approval |
| `TAI-SOD-IDM-001` | Identity creation and administrator assignment |
| `TAI-XPLAT-CICD-001` | Source control → AWS role delegation → Kubernetes control |
| `TAI-XPLAT-SECRETS-001` | CI/CD secrets → AWS role delegation → Vault secrets |

Rules are stored in
[`apps/api/src/toxic-access/rules/toxic-combinations.json`](apps/api/src/toxic-access/rules/toxic-combinations.json).

Existing AWS pathfinding rules are intentionally not copied into this
catalogue.

## Architecture

```text
                         Existing UnoSecur platform

 Uno Entities ─────┐
 Uno Scoring ──────┤
 Uno Detect ───────┼──► Integration adapters
 AWS Pathfinding ──┤              │
 Agents Service ───┘              ▼
                         IdentityAccessSnapshot
                                   │
                                   ▼
                    Toxic Access Intelligence Engine
                      ├─ SoD conflict evaluation
                      ├─ Cross-platform combinations
                      ├─ Effective-access evidence
                      └─ What-if simulation
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
              Next.js dashboard            Ollama Copilot
```

The domain depends on the `IdentityAccessSource` port rather than Prisma,
MongoDB, ClickHouse, or provider SDKs.

For the hackathon, `DemoPrismaIdentityAccessSource` translates seeded
PostgreSQL identities into the domain model. A production adapter can replace
it with Uno Entities and effective-entitlement APIs without changing the
engine.

## Technology

| Area | Technology |
| --- | --- |
| Frontend | Next.js 15, React 19, TypeScript |
| Backend | NestJS 11, TypeScript |
| MVP persistence | PostgreSQL, Prisma |
| Cache/readiness | Redis |
| Future effective-access graph | Neo4j |
| Local AI | Ollama |
| Workspace | pnpm, Turborepo |
| Validation | Jest, ESLint, TypeScript, Next.js build |

## Repository layout

```text
unosecur-pid/
├── apps/
│   ├── api/
│   │   ├── prisma/                  # MVP schema, migration, and seed data
│   │   └── src/
│   │       ├── toxic-access/        # Primary value-added domain
│   │       │   ├── adapters/        # Replaceable data-source adapters
│   │       │   ├── domain/          # Provider-neutral contracts
│   │       │   ├── dto/             # Validated API inputs
│   │       │   ├── ports/           # Integration boundaries
│   │       │   └── rules/           # Unique conflict catalogue
│   │       ├── copilot/             # Evidence-grounded Ollama interface
│   │       ├── health/              # Dependency readiness
│   │       └── risk/                # Deprecated demo compatibility API
│   └── web/                         # Dashboard and interactive Copilot UI
├── docs/
│   └── architecture/                # Product and ownership decisions
├── infrastructure/
│   └── docker/compose.yml           # Redis and Neo4j for local development
├── packages/                        # Shared-package placeholders
└── turbo.json
```

## Prerequisites

- Node.js 20 or newer
- pnpm 10
- PostgreSQL running locally on port `5432`
- Docker with Compose
- Ollama running locally

The project reuses the existing local PostgreSQL installation. It does not
start a second PostgreSQL container.

### Hackathon technology requirements

| Requirement | Minimum for the MVP | Recommended |
| --- | --- | --- |
| Operating system | macOS, Linux, or Windows with WSL2 | macOS or Linux |
| Memory | 12 GB with a 4B local model | 16 GB or more |
| Node.js | 20 | Current LTS |
| pnpm | 10 | 10 |
| PostgreSQL | 15 | 17 |
| Docker | Current supported release | Docker Desktop with Compose |
| Ollama | Local API enabled | `qwen3:4b` or `llama3:8b` |
| Browser | Current Chrome, Edge, Firefox, or Safari | Chrome |

The application uses these local ports:

| Port | Service |
| ---: | --- |
| `3000` | Next.js dashboard |
| `4000` | NestJS API |
| `5432` | PostgreSQL |
| `6379` | Redis |
| `7474` | Neo4j browser |
| `7687` | Neo4j Bolt protocol |
| `11434` | Ollama |

Internet access is needed only to install dependencies and download a local
model. Runtime identity evidence and Copilot prompts remain on the workstation.

## Local setup

### 1. Install dependencies

```bash
pnpm install
```

### 2. Configure the environment

```bash
cp .env.example .env
```

Default development values:

```dotenv
DATABASE_URL=postgresql://enterprise:enterprise_dev@localhost:5432/enterprise_ai
REDIS_URL=redis://:redis_dev@localhost:6379
NEO4J_URI=neo4j://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=neo4j_dev_password
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=llama3:8b-instruct-q4_K_M
API_PORT=4000
NEXT_PUBLIC_API_URL=http://localhost:4000/api
```

Change local credentials as required. Do not commit `.env`.

### 3. Start Redis and Neo4j

```bash
pnpm infra:up
```

Verify:

```bash
docker compose -f infrastructure/docker/compose.yml ps
```

### 4. Prepare PostgreSQL

If the database and role already exist, skip their creation.

```bash
createuser --login --pwprompt enterprise
createdb --owner=enterprise enterprise_ai
```

Generate Prisma Client and apply the committed migration:

```bash
pnpm --filter @unosecur/api prisma:generate
pnpm --filter @unosecur/api exec prisma migrate deploy
```

Load the hackathon identities:

```bash
pnpm --filter @unosecur/api prisma:seed
```

### 5. Start Ollama

```bash
ollama serve
```

In another terminal:

```bash
ollama list
curl http://localhost:11434/api/tags
```

Set `OLLAMA_MODEL` to an installed chat model. The application never downloads
a model automatically.

### 6. Run the application

```bash
pnpm dev
```

Open:

- Dashboard: <http://localhost:3000>
- API: <http://localhost:4000/api>
- Swagger: <http://localhost:4000/docs>
- Neo4j Browser: <http://localhost:7474>

## API

### Primary Toxic Access endpoints

#### List conflicted identities

```http
GET /api/toxic-access/identities
```

Returns only identities with at least one deterministic entitlement conflict.

#### Evaluate one identity

```http
GET /api/toxic-access/identities/{identityId}
```

Returns:

- Conflict rule and severity
- Business impact
- Recommended remediation
- Affected platforms
- Matched permissions and resources
- Effective-access paths
- Security-control mappings

#### Simulate permission removal

```http
POST /api/toxic-access/identities/{identityId}/simulate
Content-Type: application/json

{
  "removePermissions": ["finance:payment:approve"]
}
```

The operation is read-only. It reports projected conflict resolution and does
not alter the identity.

#### Ask Copilot

```http
POST /api/copilot/ask
Content-Type: application/json

{
  "identityId": "john-smith",
  "question": "Which permission should be removed first?"
}
```

Copilot is grounded in the Toxic Access evaluation for the selected identity.

### Deprecated compatibility endpoints

`/api/risk/*` exists temporarily so the original hackathon dashboard and seed
workflow continue to function. The Swagger operations are marked deprecated.

The local risk score, rules, and persisted findings in this module are not a
proposed replacement for Uno Scoring or Uno Detect. They will be removed after
the dashboard and production adapters no longer require them.

## Example evaluation

```json
{
  "identityId": "maya-patel",
  "displayName": "Maya Patel",
  "source": "demo-prisma",
  "summary": {
    "total": 1,
    "critical": 1,
    "high": 0,
    "affectedPlatforms": ["Entra ID"]
  },
  "conflicts": [
    {
      "ruleId": "TAI-SOD-FIN-001",
      "title": "Vendor creation and payment approval conflict",
      "severity": "critical",
      "evidence": [
        {
          "permission": "finance:vendor:create",
          "resource": "erp:vendors",
          "accessPath": [
            "Maya Patel",
            "finance-operator",
            "finance:vendor:create",
            "erp:vendors"
          ]
        }
      ]
    }
  ]
}
```

## Demo walkthrough

1. Open the command center.
2. Select **Maya Patel** to show a finance segregation-of-duties conflict.
3. Review the matched permissions and effective-access evidence.
4. Simulate removing `finance:payment:approve`.
5. Show that the conflict resolves while unrelated access remains.
6. Select **John Smith** to demonstrate a multi-platform control-plane pivot.
7. Open the floating Copilot and ask why the combination is dangerous.
8. Explain that existing UnoSecur systems supply identities, scores, and
   findings while this capability adds preventative combination analysis.

## Validation

Run the complete workspace validation:

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

Run only the API tests:

```bash
pnpm --filter @unosecur/api test
```

Current automated coverage includes:

- Complete and incomplete entitlement combinations
- Cross-platform constraints
- Effective-access evidence
- Wildcard resource matching
- Non-destructive conflict simulation
- Preservation of unrelated grants
- Existing demo compatibility behavior

## Security principles

- Deterministic engines establish findings; the LLM only explains evidence.
- Simulation never writes permission changes.
- Secrets and service URLs are configured through environment variables.
- API input is validated and stripped of unknown properties.
- Helmet security headers and explicit CORS are enabled.
- No enterprise data is sent to an external model by the MVP.
- Future remediation actions require MCP guardrails, audit records, and human
  approval.

## Known limitations

- Identity data is currently seeded through the demo Prisma adapter.
- Effective-access paths are reconstructed from demo grant sources.
- Neo4j readiness exists, but graph persistence is not yet the source of access
  paths.
- Authentication and tenant authorization are not implemented.
- The dashboard still uses the compatibility API for identity presentation
  metadata while conflict content comes from `/api/toxic-access`.
- Copilot responses are non-streaming.
- Production UnoSecur adapters are not yet implemented.

## Roadmap
- Product ownership boundary
- Provider-neutral Toxic Access contracts
- Replaceable identity-access port
- Unique rule catalogue
- Deterministic conflict engine
- Conflict-resolution simulation
- Floating Copilot launcher
- Dashboard backed by `/api/toxic-access`
- Conflict-based metrics and identity detail
- Effective-access visualization
- Copilot grounded in conflicts instead of local scores
- Uno Entities adapter
- Uno Scoring context adapter
- Uno Detect finding/evidence adapter
- Stable canonical identity identifiers
- Neo4j effective-access graph
- Direct, inherited, nested-group, delegated, and cross-account paths
- Resource-aware conflict evaluation
- Minimum-change remediation optimizer
- Risk-reduction versus business-access preservation ranking
- Role, group, boundary, and JIT what-if operations
- MCP Gateway guardrails
- Approval-controlled Jira or ServiceNow remediation requests
- Tamper-evident Copilot audit history

## Contributing

Before adding a rule or feature:

1. Confirm it is not already owned by Uno Scoring, Uno Detect, AWS pathfinding,
   Uno Events, Uno Entities, or the Agents service.
2. Add only preventive entitlement-combination logic to this project.
3. Include deterministic evidence and remediation.
4. Add unit tests.
5. Update this README and the ownership-boundary document.
6. Run the complete validation suite.

Suggested commit scopes:

```text
feat(toxic-access):
feat(simulation):
feat(copilot):
docs(architecture):
test(toxic-access):
```

## License

No project license has been selected yet. Add the appropriate organization or
open-source license before external distribution.
