# UnoSecur Identity Copilot

Hackathon MVP for explainable toxic-identity detection across cloud, Kubernetes,
source control, and enterprise identity systems.

## What works

- Executive risk dashboard with seeded multi-cloud demo data.
- UnoSecur-themed investigation workspace with selectable identities and finding filters.
- Interactive attack paths and non-destructive what-if remediation simulation.
- Floating local AI Copilot grounded in stored identity evidence.
- NestJS API with Swagger, validation, security headers, and health probes.
- Explainable toxic-identity findings and contributing risk factors.
- PostgreSQL/Prisma domain model for identities, grants, rules, and findings.
- Connectivity probes for PostgreSQL, Redis, Neo4j, and local Ollama.
- Docker Compose for Redis and Neo4j.
- Local PostgreSQL for persistent application data.

## Quick start

```bash
cp .env.example .env
pnpm install
pnpm infra:up
createuser --login --pwprompt enterprise
createdb --owner=enterprise enterprise_ai
pnpm --filter @unosecur/api prisma:generate
pnpm --filter @unosecur/api exec prisma migrate deploy
pnpm --filter @unosecur/api prisma:seed
pnpm dev
```

Open the web app at <http://localhost:3000>, the API at
<http://localhost:4000/api>, and Swagger at <http://localhost:4000/docs>.

Ollama runs on the host and is not duplicated in Docker:

```bash
ollama serve
ollama list
```

PostgreSQL runs directly on the development machine at port `5432`. The
one-time `createuser` and `createdb` commands can be skipped when those objects
already exist.

## Risk engine

The deterministic risk engine loads its security knowledge from the external
JSON rule catalogue in `apps/api/src/risk/rules/catalog.json`. Seed data
includes human and machine identities across AWS, Kubernetes, GitHub, and
enterprise finance workflows.

Useful endpoints:

- `POST /api/risk/scan` evaluates all stored identities and persists findings.
- `GET /api/risk/summary` returns dashboard metrics and toxic identities.
- `GET /api/risk/identities` lists evaluated identities.
- `GET /api/risk/identities/:id` returns one identity with evidence and findings.
- `POST /api/risk/identities/:id/simulate` previews permission-removal impact.
- `POST /api/copilot/ask` asks the locally hosted evidence-grounded Copilot.

## Validation

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

This branch is an MVP foundation. Authentication, live connector ingestion,
Neo4j attack-path persistence, and streaming AI chat are the next vertical slices.
