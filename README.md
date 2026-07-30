# UnoSecur PID

**Privilege Intelligence & Detection**

UnoSecur PID identifies dangerous combinations of
effective entitlements before they are exploited. It correlates permissions
across enterprise applications, identity providers, cloud platforms, source
control, Kubernetes, and secret stores; explains how an identity received the
access; and previews the smallest safe remediation without changing live access.

## Identity

| Item           | Name                                                                     |
| -------------- | ------------------------------------------------------------------------ |
| Product        | **UnoSecur PID — Privilege Intelligence & Detection**                    |
| Repository     | **unosecur-pid**                                                         |
| One-line pitch | Detect dangerous privilege combinations before they become attack paths. |

The platform detects toxic access combinations rather than labelling people or machine identities as inherently toxic.

## Why this exists

Access is usually reviewed one permission, role, or platform at a time. That misses combinations where individually legitimate permissions produce a dangerous capability together.

Examples include:

- Creating a vendor and approving payments to that vendor.
- Creating an identity and assigning it an administrative role.
- Administering source code, delegating a production cloud role, and
  controlling a Kubernetes cluster.
- Reading CI/CD secrets, assuming a cloud role, and reading production secrets.

UnoSecur PID evaluates effective access collectively and answers:

- Which combinations are dangerous?
- Which systems and resources participate in the conflict?
- Was each entitlement direct, inherited, or delegated?
- Which permission removal breaks the conflict?
- How much unrelated access remains after the proposed change?

## Product ownership boundary

The project deliberately does not duplicate existing UnoSecur business logic.

| Capability                                                      | System of record           |
| --------------------------------------------------------------- | -------------------------- |
| Canonical identities, NHIs, groups, resources, and integrations | Uno Entities               |
| Normalized cloud, identity, SaaS, and DevOps events             | Uno Events                 |
| Risk, policy, blast-radius, bands, and investigation priority   | Uno Scoring                |
| Findings, incidents, evidence, deduplication, and lifecycle     | Uno Detect                 |
| Existing AWS privilege-escalation pathfinding                   | UnoSecur anomaly detection |
| AI-agent, tool, and permission inventory                        | Agents service             |
| Entitlement conflicts and segregation of duties                 | **This project**           |
| Cross-platform toxic access combinations                        | **This project**           |
| What-if conflict resolution                                     | **This project**           |
| Minimum-change remediation optimization                         | **This project — roadmap** |

The complete boundary is documented in
[`docs/architecture/toxic-access-boundary.md`](docs/architecture/toxic-access-boundary.md).
The business operating modes, standards alignment, market differentiation, and
delivery phases are documented in
[`docs/PRODUCT_STRATEGY_AND_ROADMAP.md`](docs/PRODUCT_STRATEGY_AND_ROADMAP.md).

### Privilege intelligence engine

- Provider-neutral entitlement-combination model.
- Deterministic conflict evaluation.
- Human, service-account, and workload identity support.
- Platform and resource constraints.
- Cross-platform minimum-coverage conditions.
- Evidence containing permission, resource, and effective-access path.
- MITRE ATT&CK and NIST mappings.
- No locally invented production risk score.

### Visual rule builder

- Allows customer security teams to define organization-specific toxic
  combinations without editing source files.
- Builds AND conditions with OR permission alternatives, platform and resource
  scope, and User/NHI applicability.
- Captures severity, business impact, remediation, and security-control
  mappings.
- Tests draft rules against current effective-access evidence before saving.
- Keeps drafts isolated from detection until explicitly published.
- Adds published rules to the same deterministic engine used by built-in rules.
- Stores customer rules, lifecycle state, version, and publication history in
  PostgreSQL.

### What-if simulation

- Removes proposed permissions from an in-memory snapshot.
- Re-evaluates conflicts without persisting access changes.
- Reports resolved and remaining conflicts.
- Reports how many unrelated grants remain.
- Supports users and Non-Human Identities (NHI), including workloads and service accounts.
- Explains which verified toxic paths the proposed privilege removal prevents.

### Investigation experience

- Executive Overview with selectable 7, 15, 30, and 90-day posture trends.
- Daily toxic-identity, conflict, remediation, and attack-path snapshots.
- Remediation efficiency and net-risk movement indicators.
- Priority identity queue.
- User and NHI filters with risky machine-action context.
- Severity-filtered entitlement conflicts.
- Interactive effective-access path.
- Floating, animated UnoSecur Copilot.
- Responsive layout and reduced-motion accessibility.

### Local LLM

- Uses Ollama through its local HTTP API.
- Receives deterministic Toxic Access evidence.
- Explains business impact and remediation.
- Answers evidence-backed questions about rules, NHI risk, simulations, and 30-day remediation trends.
- Falls back to a deterministic evidence summary if Ollama is unavailable.
- Does not create scores, permissions, findings, or severity.

## Conflict catalogue

The catalogue currently contains 14 deterministic rules covering:

- Financial and identity-administration separation of duties.
- AWS privilege delegation, audit tampering, data movement, standing
  credentials, and KMS lifecycle abuse.
- Kubernetes RBAC escalation, workload creation, and secret access.
- GitHub administration, workflow control, and branch-protection bypass.
- Entra application registration, credential management, and tenant consent.
- Vault policy and token issuance.
- Cross-platform CI/CD, secret, cloud, backup, and production-control paths.

Rules are stored in
[`apps/api/src/toxic-access/rules/toxic-combinations.json`](apps/api/src/toxic-access/rules/toxic-combinations.json).

### Capability coverage

| Required capability                      | Status   | Implementation                                                       |
| ---------------------------------------- | -------- | -------------------------------------------------------------------- |
| At least five defined toxic rules        | Complete | 14 version-controlled deterministic rules                            |
| Scan identities for combinations         | Complete | Provider-neutral effective-grant evaluation                          |
| Identity, rule, and permission evidence  | Complete | Toxic Access API and identity investigation                          |
| Risk narrative and attack scenario       | Complete | Business impact plus evidence-grounded Copilot explanation           |
| Critical, high, and medium severity      | Complete | Rule-defined severity with UI filtering                              |
| At least one cloud permission model      | Complete | AWS IAM/KMS plus Kubernetes, GitHub, Entra, Vault, GCP, and others   |
| Remediation suggestions                  | Complete | Rule remediation and permission-removal simulation                   |
| Cross-platform detection                 | Complete | Minimum-platform and platform-specific rule constraints              |
| Custom rule authoring interface          | Complete | Visual builder, evidence preview, draft lifecycle, and publication   |
| SoD matrix visualization                 | Planned  | Deterministic SoD rules exist; matrix visualization is not yet added |
| Historical posture and remediation trend | Complete | Daily 90-day snapshots with selectable executive reporting periods   |
| First-acquired entitlement timeline      | Planned  | Entitlement acquisition history awaits connected platform events     |

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
                       UnoSecur PID Engine
                      ├─ SoD conflict evaluation
                      ├─ Cross-platform combinations
                      ├─ Effective-access evidence
                      └─ What-if simulation
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
              Next.js dashboard            Ollama Copilot
```

## Technology

| Area                          | Technology                              |
| ----------------------------- | --------------------------------------- |
| Frontend                      | Next.js 15, React 19, TypeScript        |
| Backend                       | NestJS 11, TypeScript                   |
| MVP persistence               | PostgreSQL, Prisma                      |
| Cache/readiness               | Redis                                   |
| Future effective-access graph | Neo4j                                   |
| Local AI                      | Ollama                                  |
| Workspace                     | pnpm, Turborepo                         |
| Validation                    | Jest, ESLint, TypeScript, Next.js build |

## Prerequisites

- Node.js 20 or newer
- pnpm 10
- PostgreSQL running locally on port `5432`
- Docker with Compose
- Ollama running locally

Reuses the existing local PostgreSQL installation. It does not start a second PostgreSQL container.

### Technology requirements

| Requirement      | Minimum for the MVP                      | Recommended                 |
| ---------------- | ---------------------------------------- | --------------------------- |
| Operating system | macOS, Linux, or Windows with WSL2       | macOS or Linux              |
| Memory           | 12 GB with a 4B local model              | 16 GB or more               |
| Node.js          | 20                                       | Current LTS                 |
| pnpm             | 10                                       | 10                          |
| PostgreSQL       | 15                                       | 17                          |
| Docker           | Current supported release                | Docker Desktop with Compose |
| Ollama           | Local API enabled                        | `qwen3:4b` or `llama3:8b`   |
| Browser          | Current Chrome, Edge, Firefox, or Safari | Chrome                      |

The application uses these local ports:

|    Port | Service             |
| ------: | ------------------- |
|  `3000` | Next.js dashboard   |
|  `4000` | NestJS API          |
|  `5432` | PostgreSQL          |
|  `6379` | Redis               |
|  `7474` | Neo4j browser       |
|  `7687` | Neo4j Bolt protocol |
| `11434` | Ollama              |

Internet access is needed only to install dependencies and download a local model. Runtime identity evidence and Copilot prompts remain on the workstation.

## Setup

### Portable deployment — recommended

The portable deployment requires only Docker. The deployment script detects the
operating system, installs Docker where the host package manager supports it,
creates private credentials, builds the API and dashboard, starts PostgreSQL,
Redis, and Neo4j, applies Prisma migrations, loads the demonstration dataset,
and serves the application.

macOS, Linux, or Windows Subsystem for Linux:

```bash
./scripts/deploy.sh
```

Native Windows PowerShell:

```powershell
.\scripts\deploy.ps1
```

Open the dashboard at <http://localhost:3000>. No host installation of Node.js,
pnpm, PostgreSQL, Redis, or Neo4j is required. Ollama is optional; when it is
not running, PID uses its evidence-grounded deterministic narrative engine.

Deployment operations:

```bash
./scripts/deploy.sh status
./scripts/deploy.sh logs
./scripts/deploy.sh down
```

To expose PID to other devices on a trusted network, provide the host name or
address before the first deployment:

```bash
PID_PUBLIC_HOST=pid.example.internal ./scripts/deploy.sh
```

For internet-facing production use, place PID behind an authenticated TLS
reverse proxy and replace the generated development secrets with managed
secrets. The single-command deployment is intended for local demonstrations,
evaluation environments, and controlled internal deployments.

### One-command workflow

The lifecycle runner is the recommended way to operate the complete local
developer environment when PostgreSQL, Node.js, pnpm, and Ollama are already
installed on the host:

```bash
./scripts/pid.sh all
```

This installs dependencies, starts Redis and Neo4j, verifies the existing
PostgreSQL database, generates Prisma Client, applies migrations, seeds the
demo, checks Ollama, and starts the API and dashboard.

Other lifecycle commands:

```bash
./scripts/pid.sh setup
./scripts/pid.sh start
./scripts/pid.sh status
./scripts/pid.sh validate
./scripts/pid.sh stop
```

Equivalent pnpm aliases are available as `pnpm pid:setup`,
`pnpm pid:start`, `pnpm pid:status`, `pnpm pid:validate`, and
`pnpm pid:stop`.

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

Set `OLLAMA_MODEL` to an installed chat model. The application never downloads a model automatically.

### 6. Run the application

```bash
pnpm dev
```

Open:

- Dashboard: <http://localhost:3000>
- API: <http://localhost:4000/api>
- Swagger: <http://localhost:4000/docs>

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
          "accessPath": ["Maya Patel", "finance-operator", "finance:vendor:create", "erp:vendors"]
        }
      ]
    }
  ]
}
```

## Walkthrough

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
- Future remediation actions require MCP guardrails, audit records, and human approval.

## Known limitations

- Identity data is currently seeded through the demo Prisma adapter.
- Effective-access paths are reconstructed from demo grant sources.
- Neo4j readiness exists, but graph persistence is not yet the source of access paths.
- Authentication and tenant authorization are not implemented.
- The dashboard still uses the compatibility API for identity presentation metadata while conflict content comes from `/api/toxic-access`.
- Copilot responses are non-streaming.
- Production UnoSecur adapters are not yet implemented.

## Roadmap

PID develops through eight business-aligned phases: explainable combination
detection, governed SoD management, production adapters, privilege history,
advanced graph and NHI intelligence, remediation orchestration, enterprise
governance, and production scale. See the
[product strategy and roadmap](docs/PRODUCT_STRATEGY_AND_ROADMAP.md) for the
operating modes, corporate stakeholders, standards alignment, measurable
outcomes, market USP, and detailed delivery plan.

### Foundation and unique domain boundary

- Provider-neutral privilege and entitlement contracts.
- Replaceable identity-access source.
- Deterministic combination catalogue and conflict engine.
- Explicit ownership boundary with the existing UnoSecur repositories.

### Investigation experience

- Conflict-based executive dashboard and identity investigation.
- Effective-access evidence visualization.
- Non-destructive permission-removal simulation.
- Evidence-grounded local Ollama Copilot with deterministic fallback.
- Animated, accessible floating Copilot launcher.

### Effective-access graph

- Persist identities, groups, roles, policies, grants, and resources in Neo4j.
- Resolve direct, inherited, nested-group, delegated, impersonated, and
  cross-account access.
- Evaluate conflicts using resource scope and graph-derived evidence.
- Visualize multiple alternative paths and their shared control points.

### Remediation intelligence

- Minimum-change remediation optimizer.
- Rank risk reduction against preserved business access.
- Simulate role, group, permission-boundary, and just-in-time changes.
- Compare multiple proposed remediations side by side.

### Governed enterprise workflows

- Authentication, tenant authorization, and data-boundary enforcement.
- MCP gateway with tool allowlists and human approval.
- Approval-controlled Jira or ServiceNow remediation requests.
- Tamper-evident Copilot investigation and action history.
- Operational monitoring, performance tests, and deployment packaging.

## Further enhancement

| Enhancement                    | Value added by PID                                                                         |
| ------------------------------ | ------------------------------------------------------------------------------------------ |
| Privilege drift timeline       | Shows exactly when an identity became dangerous and which grant completed the conflict.    |
| Conflict clusters              | Groups identities sharing the same dangerous entitlement pattern and remediation point.    |
| Identity digital twin          | Tests future role, group, and policy changes against a read-only access model.             |
| Break-glass awareness          | Distinguishes approved emergency privilege from unexplained standing access.               |
| Time-bound access reasoning    | Evaluates temporary, scheduled, expired, and just-in-time grants.                          |
| Compensating controls          | Adjusts remediation guidance when MFA, approval, session recording, or PAM controls exist. |
| Business-process rule packs    | Adds finance, HR, engineering, data, and infrastructure separation-of-duties packs.        |
| Rule provenance and versioning | Makes every decision reproducible against the exact catalogue and source evidence.         |
| Change-impact API              | Allows CI/CD and IaC pipelines to test whether a proposed change creates a new conflict.   |
| Remediation portfolio          | Finds one controlled change that resolves the greatest number of conflicts safely.         |
| Continuous evaluation          | Re-evaluates only identities affected by new grants rather than rescanning everything.     |
| Executive narratives           | Converts deterministic conflict evidence into concise business-impact summaries.           |
