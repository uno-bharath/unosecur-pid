# UnoSecur Identity Copilot

Hackathon MVP for explainable toxic-identity detection across cloud, Kubernetes,
source control, and enterprise identity systems.

## What works

- Executive risk dashboard with seeded multi-cloud demo data.
- NestJS API with Swagger, validation, security headers, and health probes.
- Explainable toxic-identity findings and contributing risk factors.
- PostgreSQL/Prisma domain model for identities, grants, rules, and findings.
- Connectivity probes for PostgreSQL, Redis, Neo4j, and local Ollama.
- Docker Compose for PostgreSQL, Redis, and Neo4j.

## Quick start

```bash
cp .env.example .env
pnpm install
pnpm infra:up
pnpm --filter @unosecur/api prisma:generate
pnpm dev
```

Open the web app at <http://localhost:3000>, the API at
<http://localhost:4000/api>, and Swagger at <http://localhost:4000/docs>.

Ollama runs on the host and is not duplicated in Docker:

```bash
ollama serve
ollama list
```

## Validation

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

This branch is an MVP foundation. Authentication, live connector ingestion,
Neo4j attack-path persistence, and streaming AI chat are the next vertical slices.
