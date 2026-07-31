/**
 * Pulls live identities from ClickHouse, enriches sparse entitlements with
 * deterministic toxic grant packs, and upserts them into Postgres for the demo MVP.
 *
 * Usage: pnpm --filter @unosecur/api prisma:sync-clickhouse
 */
import { IdentityType, Prisma, PrismaClient, Severity } from '@prisma/client';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { RiskEngineService } from '../src/risk/risk-engine.service';
import { RuleCatalogService } from '../src/risk/rule-catalog.service';
import { RiskSeverity } from '../src/risk/risk.types';
import {
  attackPathForGrants,
  enrichSparseGrants,
  hashIdentity,
} from '../src/toxic-access/adapters/demo-toxic-grant-packs';
import { EffectiveGrant } from '../src/toxic-access/domain/toxic-access.types';

function loadEnvFile(path: string): void {
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const separator = trimmed.indexOf('=');
    if (separator <= 0) continue;
    const key = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim();
    if (!(key in process.env)) process.env[key] = value;
  }
}

loadEnvFile(resolve(__dirname, '../../../.env'));
loadEnvFile(resolve(__dirname, '../.env'));

const prisma = new PrismaClient();
const engine = new RiskEngineService();
const catalog = new RuleCatalogService();

const severityMap: Record<RiskSeverity, Severity> = {
  critical: Severity.CRITICAL,
  high: Severity.HIGH,
  medium: Severity.MEDIUM,
  low: Severity.LOW,
};

interface ClickHouseIdentityRow {
  _id: string;
  correlation_uno_id: string | null;
  name: string;
  first_name: string | null;
  last_name: string | null;
  email: string | null;
  uno_type: string | null;
  provider_entity_type: string;
  source: string | null;
  risk_score: number | null;
  external_identifier: string | null;
  idp: string | null;
  tenant_identity_provider_name: string | null;
  details: string | null;
}

const LIMIT = Number(process.env.CLICKHOUSE_SYNC_LIMIT ?? 60);

const FAKE_CUSTOM_RULES = [
  {
    ruleId: 'CUSTOM-DEMO-AWS-BREAKGLASS-001',
    title: 'Break-glass admin with audit suppression',
    description: 'Administrator access combined with CloudTrail stop/delete is a toxic break-glass pattern.',
    category: 'CROSS_PLATFORM_CONTROL',
    severity: Severity.CRITICAL,
    businessImpact: 'An attacker can gain full account control and erase forensic trails.',
    remediation: 'Split break-glass from audit administration and require dual control.',
    identityTypes: ['HUMAN', 'SERVICE_ACCOUNT', 'WORKLOAD'],
    requirements: [
      { id: 'admin', anyPermissions: ['aws:AdministratorAccess', 'aws:*'] },
      { id: 'audit', anyPermissions: ['cloudtrail:StopLogging', 'cloudtrail:DeleteTrail'] },
    ],
    mappings: {
      mitre: ['T1562.008 Disable Cloud Logs', 'T1078.004 Cloud Accounts'],
      nist: ['AU-9 Protection of Audit Information', 'AC-6 Least Privilege'],
    },
  },
  {
    ruleId: 'CUSTOM-DEMO-IDM-APP-001',
    title: 'App registration with admin consent',
    description: 'Creating applications and granting admin consent enables persistent tenant backdoors.',
    category: 'SEGREGATION_OF_DUTIES',
    severity: Severity.HIGH,
    businessImpact: 'A malicious identity can plant a long-lived application credential with broad consent.',
    remediation: 'Separate app registration from admin consent and require independent approval.',
    identityTypes: ['HUMAN', 'SERVICE_ACCOUNT'],
    requirements: [
      { id: 'app-create', anyPermissions: ['entra:application:create'] },
      { id: 'consent', anyPermissions: ['entra:admin-consent:grant'] },
    ],
    mappings: {
      mitre: ['T1098 Account Manipulation'],
      nist: ['AC-5 Separation of Duties'],
    },
  },
  {
    ruleId: 'CUSTOM-DEMO-XPLAT-SECRETS-001',
    title: 'Cluster admin reading production secrets',
    description: 'Kubernetes cluster administration with production secret read is a high-blast toxic pair.',
    category: 'DATA_CONTROL_CONFLICT',
    severity: Severity.CRITICAL,
    businessImpact: 'Compromise yields both control-plane authority and secret material.',
    remediation: 'Remove secret read from cluster-admin paths; use short-lived secret injection.',
    identityTypes: ['SERVICE_ACCOUNT', 'WORKLOAD', 'HUMAN'],
    requirements: [
      { id: 'cluster', anyPermissions: ['k8s:cluster-admin', 'k8s:escalate'] },
      { id: 'secrets', anyPermissions: ['k8s:secrets:read', 'vault:secrets:read'] },
    ],
    mappings: {
      mitre: ['T1552 Unsecured Credentials', 'T1078 Valid Accounts'],
      nist: ['AC-6 Least Privilege', 'SC-28 Protection of Information at Rest'],
    },
  },
] as const;

function canonicalProvider(provider: string): string {
  const normalized = provider.trim().toUpperCase();
  const names: Record<string, string> = {
    AWS: 'AWS',
    GCP: 'GCP',
    AZURE: 'Azure',
    ENTRA: 'Entra ID',
    GITHUB: 'GitHub',
    'GITHUB-EMU': 'GitHub',
    KUBERNETES: 'Kubernetes',
    'HASHI-CORP': 'Vault',
    'ACTIVE-DIRECTORY': 'Entra ID',
    'GOOGLE-WORKSPACE': 'Google Workspace',
  };
  return names[normalized] ?? (provider.trim() || 'UNKNOWN');
}

function identityType(row: ClickHouseIdentityRow): IdentityType {
  if (row.uno_type === 'provider_identity_human' || /USER/i.test(row.provider_entity_type)) {
    return IdentityType.HUMAN;
  }
  if (/workload|pod|function|application|agent/i.test(row.provider_entity_type)) {
    return IdentityType.WORKLOAD;
  }
  return IdentityType.SERVICE_ACCOUNT;
}

function displayName(row: ClickHouseIdentityRow): string {
  const composed = [row.first_name, row.last_name].filter(Boolean).join(' ').trim();
  return composed || row.email?.trim() || row.name?.trim() || row.external_identifier || row._id;
}

function departmentFor(row: ClickHouseIdentityRow): string {
  return (
    row.tenant_identity_provider_name?.trim() ||
    row.idp?.trim() ||
    row.source?.trim() ||
    'Connected platform'
  );
}

function emailFor(row: ClickHouseIdentityRow): string | null {
  if (row.email?.trim()) return row.email.trim();
  if (row.name.includes('@')) return row.name.trim();
  return null;
}

async function queryClickHouse<T>(sql: string): Promise<T[]> {
  const baseUrl = (process.env.CLICKHOUSE_URL ?? 'http://127.0.0.1:8123').replace(/\/$/, '');
  const username = process.env.CLICKHOUSE_USERNAME ?? 'default';
  const password = process.env.CLICKHOUSE_PASSWORD ?? '';
  const response = await fetch(baseUrl, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`,
      'Content-Type': 'text/plain; charset=utf-8',
    },
    body: sql,
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {
    throw new Error(`ClickHouse returned HTTP ${response.status}: ${await response.text()}`);
  }
  return (await response.text())
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as T);
}

async function seedCustomRules(): Promise<void> {
  for (const rule of FAKE_CUSTOM_RULES) {
    await prisma.customToxicRule.upsert({
      where: { ruleId: rule.ruleId },
      update: {
        title: rule.title,
        description: rule.description,
        category: rule.category,
        severity: rule.severity,
        businessImpact: rule.businessImpact,
        remediation: rule.remediation,
        requirements: rule.requirements as unknown as Prisma.InputJsonValue,
        identityTypes: [...rule.identityTypes],
        mappings: rule.mappings as unknown as Prisma.InputJsonValue,
        status: 'PUBLISHED',
        publishedAt: new Date(),
      },
      create: {
        ruleId: rule.ruleId,
        title: rule.title,
        description: rule.description,
        category: rule.category,
        severity: rule.severity,
        businessImpact: rule.businessImpact,
        remediation: rule.remediation,
        requirements: rule.requirements as unknown as Prisma.InputJsonValue,
        identityTypes: [...rule.identityTypes],
        mappings: rule.mappings as unknown as Prisma.InputJsonValue,
        status: 'PUBLISHED',
        publishedAt: new Date(),
        createdBy: 'ClickHouse demo sync',
      },
    });
  }
}

async function upsertIdentity(row: ClickHouseIdentityRow): Promise<void> {
  const provider = canonicalProvider(row.source || row.provider_entity_type.split(' - ')[0] || 'UNKNOWN');
  const id = `ch:${(row.correlation_uno_id || row._id).slice(0, 48)}`;
  const name = displayName(row);
  const grants = enrichSparseGrants(id, name, provider, [] as EffectiveGrant[], 0);
  const type = identityType(row);
  const attackPath = attackPathForGrants(name, grants);
  const riskHint = Math.min(100, Math.round((row.risk_score ?? 0) + 40 + (hashIdentity(id) % 45)));

  const externalId = row.external_identifier || row._id;
  const blastRadius = {
    accounts: new Set(grants.map((grant) => grant.platform)).size,
    clusters: grants.some((grant) => grant.platform === 'Kubernetes') ? 2 : 0,
    secrets: grants.filter((grant) => /secret|key|token|kms/i.test(grant.permission)).length,
    databases: grants.filter((grant) => /database|sql|rds|postgres/i.test(grant.permission))
      .length,
  };
  const identity = await prisma.identity.upsert({
    where: { provider_externalId: { provider, externalId } },
    update: {
      displayName: name,
      email: emailFor(row),
      type,
      department: departmentFor(row),
      blastRadius,
      attackPath,
      lastActiveAt: new Date(),
    },
    create: {
      id,
      externalId,
      displayName: name,
      email: emailFor(row),
      type,
      provider,
      department: departmentFor(row),
      blastRadius,
      attackPath,
      lastActiveAt: new Date(),
    },
  });

  await prisma.grant.deleteMany({ where: { identityId: identity.id } });
  await prisma.grant.createMany({
    data: grants.map((grant) => ({
      identityId: identity.id,
      platform: grant.platform,
      permission: grant.permission,
      resource: grant.resource,
      source: grant.assignment.source,
    })),
  });

  const stored = await prisma.identity.findUniqueOrThrow({
    where: { id: identity.id },
    include: { grants: true },
  });
  const rules = catalog.getRules();
  const matches = engine.evaluate(stored, rules);
  await prisma.identity.update({
    where: { id: identity.id },
    data: {
      riskScore: Math.max(riskHint, engine.calculateScore(matches)),
      confidence: engine.calculateConfidence(matches) || 0.85,
    },
  });
  await prisma.finding.deleteMany({ where: { identityId: identity.id } });
  if (matches.length > 0) {
    await prisma.finding.createMany({
      data: matches.map((match) => ({
        identityId: identity.id,
        ruleId: match.rule.id,
        severity: severityMap[match.rule.severity],
        confidence: match.rule.confidence,
        evidence: match.evidence as Prisma.InputJsonValue,
      })),
    });
  }
}

async function refreshPostureFromFindings(): Promise<void> {
  const toxicIdentities = await prisma.identity.count({ where: { findings: { some: {} } } });
  const totalConflicts = await prisma.finding.count();
  const criticalConflicts = await prisma.finding.count({ where: { severity: Severity.CRITICAL } });
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);

  for (let index = 0; index < 90; index += 1) {
    const snapshotDate = new Date(today.getTime() - (89 - index) * 86_400_000);
    const progress = index / 89;
    const toxic = Math.max(
      3,
      Math.round(toxicIdentities * (1.55 - progress * 0.55) + ((index * 7) % 3)),
    );
    const conflicts = Math.max(
      toxic,
      Math.round(totalConflicts * (1.4 - progress * 0.4) + ((index * 5) % 4)),
    );
    const critical = Math.max(
      1,
      Math.round(criticalConflicts * (1.35 - progress * 0.35) + (index % 2)),
    );
    await prisma.postureSnapshot.upsert({
      where: { snapshotDate },
      update: {
        toxicIdentities: toxic,
        totalConflicts: conflicts,
        criticalConflicts: critical,
        newConflicts: index % 6 === 0 ? 2 : index % 3 === 0 ? 1 : 0,
        remediatedConflicts: index > 40 && index % 2 === 0 ? 1 + (index % 3) : index % 5 === 0 ? 1 : 0,
        attackPaths: Math.max(2, toxic + 1),
      },
      create: {
        snapshotDate,
        toxicIdentities: toxic,
        totalConflicts: conflicts,
        criticalConflicts: critical,
        newConflicts: index % 6 === 0 ? 2 : index % 3 === 0 ? 1 : 0,
        remediatedConflicts: index > 40 && index % 2 === 0 ? 1 + (index % 3) : index % 5 === 0 ? 1 : 0,
        attackPaths: Math.max(2, toxic + 1),
      },
    });
  }
}

async function main(): Promise<void> {
  const database = process.env.CLICKHOUSE_DATABASE;
  if (!database) {
    throw new Error('CLICKHOUSE_DATABASE is required');
  }

  console.log(`Syncing up to ${LIMIT} ClickHouse identities into Postgres…`);
  const rows = await queryClickHouse<ClickHouseIdentityRow>(`
    SELECT
      _id,
      correlation_uno_id,
      name,
      first_name,
      last_name,
      email,
      uno_type,
      provider_entity_type,
      source,
      risk_score,
      external_identifier,
      idp,
      tenant_identity_provider_name,
      details
    FROM \`${database}\`.uno_entities FINAL
    WHERE uno_type IN ('provider_identity_human', 'provider_identity_nhi')
       OR positionCaseInsensitive(provider_entity_type, 'USER') > 0
       OR positionCaseInsensitive(provider_entity_type, 'NHI') > 0
    ORDER BY
      multiIf(source IN ('AWS','ENTRA','GCP','AZURE','GITHUB','GITHUB-EMU','KUBERNETES','HASHI-CORP'), 0, 1),
      updated_at DESC
    LIMIT ${LIMIT}
    FORMAT JSONEachRow
  `);

  const rules = catalog.getRules();
  for (const rule of rules) {
    await prisma.riskRule.upsert({
      where: { id: rule.id },
      update: {
        ...rule,
        severity: severityMap[rule.severity],
        matching: rule.matching as Prisma.InputJsonValue,
      },
      create: {
        ...rule,
        severity: severityMap[rule.severity],
        matching: rule.matching as Prisma.InputJsonValue,
      },
    });
  }

  await seedCustomRules();

  const seen = new Set<string>();
  let synced = 0;
  for (const row of rows) {
    const key = row.correlation_uno_id || row._id;
    if (seen.has(key)) continue;
    seen.add(key);
    await upsertIdentity(row);
    synced += 1;
  }

  await refreshPostureFromFindings();
  console.log(`Synced ${synced} identities, published ${FAKE_CUSTOM_RULES.length} demo toxic rules, refreshed 90-day posture.`);
}

main()
  .then(() => prisma.$disconnect())
  .catch(async (error: unknown) => {
    console.error(error);
    await prisma.$disconnect();
    process.exitCode = 1;
  });
