# UnoSecur ClickHouse integration

## Purpose

PID should consume UnoSecur's normalized tenant evidence instead of collecting
the same information independently from every cloud and SaaS connector. This
keeps UnoSecur Entities, Events, Detect, and connector services authoritative
while PID adds toxic-combination reasoning and non-destructive remediation
simulation.

## Data flow

```text
AWS / Azure / GCP / Kubernetes / SaaS connectors
                         |
                         v
          UnoSecur ingestion and normalization
                         |
                         v
              Tenant ClickHouse database
                         |
                         v
        PID read-only normalization adapter
                         |
                         v
  Toxic rules -> evidence -> what-if -> dashboard
```

## Security requirements

- Use a dedicated read-only ClickHouse account scoped to one development tenant.
- Permit `SELECT` only on the required tenant database, tables, and approved views.
- Prefer a curated view for PID instead of granting broad access to raw tables.
- Store credentials in `.env.local`, Vault, or a Kubernetes Secret.
- Never commit credentials, tokens, kubeconfigs, or port-forward scripts containing secrets.
- Use TLS when connecting through a routable endpoint.
- Keep tenant identity in server-side configuration; never accept a database name from a browser request.
- Apply query timeouts, row limits, and tenant filters to every read.

## Local connection to GKE development

The safest local development path is a temporary Kubernetes port-forward to the
ClickHouse HTTP service. Keep the terminal session open while PID is running:

```bash
kubectl config use-context <gke-dev-context>
kubectl -n <clickhouse-namespace> port-forward svc/<clickhouse-http-service> 8123:8123
```

Configure `.env.local` without committing it:

```dotenv
CLICKHOUSE_ENABLED=true
CLICKHOUSE_URL=http://127.0.0.1:8123
CLICKHOUSE_USERNAME=pid_readonly
CLICKHOUSE_PASSWORD=<local-secret>
CLICKHOUSE_DATABASE=unosecur_organization_<tenant-uno-id>
CLICKHOUSE_REQUEST_TIMEOUT_MS=10000
CLICKHOUSE_REFRESH_INTERVAL_SECONDS=15
CLICKHOUSE_SECURE=false
```

Use an approved internal TLS endpoint instead of port-forwarding when available.

## Existing UnoSecur data to reuse

Repository inspection confirms tenant-scoped ClickHouse data and migrations for:

- `uno_entities` and `provider_identities` for human and non-human identities.
- `uno_integrations` for connected cloud and SaaS control planes.
- `provider_resources` for target resources.
- `findings`, `findings_evidence`, and event tables for security evidence and history.
- Tenant databases following `unosecur_organization_<tenant-id>`.

The exact effective-entitlement mapping must be verified against the selected
development tenant because permissions may be represented inside normalized
JSON details/attributes or through provider-specific evidence.

## Recommended PID read model

Create or approve a tenant-scoped view with one row per effective grant:

| Column              | Purpose                                                       |
| ------------------- | ------------------------------------------------------------- |
| `identity_id`       | Stable UnoSecur identity identifier                           |
| `identity_name`     | Display name                                                  |
| `identity_type`     | Human, service account, workload, or other NHI                |
| `provider`          | AWS, Azure, GCP, GitHub, Kubernetes, SaaS, and others         |
| `permission`        | Normalized effective action or entitlement                    |
| `resource`          | Normalized resource identifier or scope                       |
| `assignment_source` | Role, group, policy, direct grant, token, or workload binding |
| `access_path`       | Ordered identity-to-resource privilege path                   |
| `observed_at`       | Evidence freshness timestamp                                  |
| `tenant_uno_id`     | Mandatory tenant boundary                                     |

This view gives PID a stable contract even when individual connector schemas evolve.

## Real-time behavior

- Refresh connector coverage and current toxic combinations every 15 seconds for the prototype.
- Read only records changed since the last watermark where timestamps are available.
- Use UnoSecur Events or a message stream for push-based production evaluation.
- Use ClickHouse for current analytical state and historical trends, not as the command path for remediation.
- Preserve evidence timestamps so the dashboard can show freshness and stale-source warnings.

## Validation before enabling production evidence

1. Confirm GKE network access and the ClickHouse HTTP endpoint.
2. Create the least-privileged `pid_readonly` account.
3. Confirm the tenant database name.
4. Inspect table columns with `DESCRIBE TABLE` using metadata-only access.
5. Validate human and NHI identity samples from each major provider.
6. Confirm where effective permissions, resources, and assignment paths are stored.
7. Compare normalized counts with the existing UnoSecur IAM dashboard.
8. Run PID in shadow mode and verify conflicts before exposing findings to users.

## Credential incident note

Plaintext ClickHouse credentials were found in a repository backup directory
during source inspection. Treat those values as exposed: rotate them, remove the
files from the repository, and purge the secrets from Git history using the
organization's approved incident process.
