import { IdentityType, Prisma, PrismaClient, Severity } from '@prisma/client';
import { RiskEngineService } from '../src/risk/risk-engine.service';
import { RuleCatalogService } from '../src/risk/rule-catalog.service';
import { RiskSeverity } from '../src/risk/risk.types';

const prisma = new PrismaClient();
const engine = new RiskEngineService();
const catalog = new RuleCatalogService();

const severityMap: Record<RiskSeverity, Severity> = {
  critical: Severity.CRITICAL,
  high: Severity.HIGH,
  medium: Severity.MEDIUM,
  low: Severity.LOW,
};

const demoIdentities = [
  {
    id: 'john-smith',
    externalId: 'entra:john.smith',
    displayName: 'John Smith',
    email: 'john.smith@example.test',
    type: IdentityType.HUMAN,
    provider: 'Entra ID',
    department: 'Platform Engineering',
    lastActiveAt: new Date(Date.now() - 2 * 86_400_000),
    blastRadius: { accounts: 8, clusters: 12, secrets: 180, databases: 4 },
    attackPath: [
      'John Smith',
      'GitHub Owner',
      'Actions Secret',
      'AWS Production Role',
      'EKS Admin',
      'Vault Secrets',
      'Customer Database',
    ],
    grants: [
      ['AWS', 'aws:AdministratorAccess', 'aws:account:production', 'PlatformAdmin'],
      ['AWS', 'iam:PassRole', 'aws:role:production-admin', 'PlatformAdmin'],
      ['AWS', 'lambda:CreateFunction', 'aws:account:production', 'PlatformAdmin'],
      ['Kubernetes', 'k8s:cluster-admin', 'k8s:cluster:prod-eks', 'cluster-admin'],
      ['Kubernetes', 'k8s:bind', 'k8s:cluster:prod-eks', 'rbac-manager'],
      ['Kubernetes', 'k8s:escalate', 'k8s:cluster:prod-eks', 'rbac-manager'],
      ['GitHub', 'github:repo:admin', 'github:uno/prod-app', 'org-owner'],
      ['GitHub', 'github:branch-protection:write', 'github:uno/prod-app/main', 'org-owner'],
      ['GitHub', 'github:actions:secrets:read', 'github:uno/prod-app', 'org-owner'],
      ['Vault', 'vault:secrets:read', 'vault:production/*', 'vault-admin'],
    ],
  },
  {
    id: 'prod-deploy-bot',
    externalId: 'github-actions:prod-deploy',
    displayName: 'prod-deploy-bot',
    email: null,
    type: IdentityType.WORKLOAD,
    provider: 'GitHub',
    department: 'Engineering',
    lastActiveAt: new Date(),
    blastRadius: { accounts: 3, clusters: 7, secrets: 64, databases: 2 },
    attackPath: ['GitHub Actions', 'Static AWS Key', 'Production Role', 'EKS Cluster Admin'],
    grants: [
      ['GitHub', 'credential:static', 'github:uno/prod-app', 'repository-secret'],
      ['GitHub', 'github:workflow:write', 'github:uno/prod-app', 'workflow'],
      ['GitHub', 'github:actions:secrets:read', 'github:uno/prod-app', 'workflow'],
      ['AWS', 'iam:PassRole', 'aws:role:prod-deployer', 'access-key'],
      ['AWS', 'lambda:CreateFunction', 'aws:account:production', 'access-key'],
      ['Kubernetes', 'k8s:cluster-admin', 'k8s:cluster:prod-eks', 'deployment-role'],
      ['Kubernetes', 'k8s:secrets:read', 'k8s:namespace:production', 'deployment-role'],
      ['Kubernetes', 'k8s:pods:create', 'k8s:namespace:production', 'deployment-role'],
      ['Vault', 'vault:secrets:read', 'vault:production/*', 'deployment-role'],
    ],
  },
  {
    id: 'maya-patel',
    externalId: 'entra:maya.patel',
    displayName: 'Maya Patel',
    email: 'maya.patel@example.test',
    type: IdentityType.HUMAN,
    provider: 'Entra ID',
    department: 'Finance',
    lastActiveAt: new Date(Date.now() - 1 * 86_400_000),
    blastRadius: { accounts: 2, clusters: 0, secrets: 12, databases: 3 },
    attackPath: ['Maya Patel', 'Finance Operator', 'Create Vendor', 'Approve Payment'],
    grants: [
      ['Entra ID', 'finance:vendor:create', 'erp:vendors', 'finance-operator'],
      ['Entra ID', 'finance:payment:approve', 'erp:payments', 'finance-approver'],
      ['AWS', 's3:GetObject', 's3:customer-data/finance/*', 'finance-data-reader'],
      ['AWS', 's3:PutObject', 's3:external-exchange/finance/*', 'data-exchange-role'],
    ],
  },
  {
    id: 'alex-chen',
    externalId: 'entra:alex.chen',
    displayName: 'Alex Chen',
    email: 'alex.chen@example.test',
    type: IdentityType.HUMAN,
    provider: 'Entra ID',
    department: 'Identity Operations',
    lastActiveAt: new Date(Date.now() - 4 * 86_400_000),
    blastRadius: { accounts: 1, clusters: 0, secrets: 5, databases: 1 },
    attackPath: ['Alex Chen', 'Identity Operator', 'Create Backdoor Admin'],
    grants: [
      ['Entra ID', 'identity:user:create', 'tenant:enterprise', 'user-admin'],
      ['Entra ID', 'identity:admin:assign', 'tenant:enterprise', 'role-admin'],
      ['Entra ID', 'entra:application:create', 'tenant:enterprise', 'app-admin'],
      ['Entra ID', 'entra:application:credentials:write', 'tenant:enterprise', 'app-admin'],
      ['Entra ID', 'entra:admin-consent:grant', 'tenant:enterprise', 'consent-admin'],
      ['AWS', 'iam:CreateAccessKey', 'aws:account:shared-services', 'iam-operator'],
    ],
  },
  {
    id: 'legacy-admin',
    externalId: 'aws:legacy-admin',
    displayName: 'legacy-admin',
    email: null,
    type: IdentityType.SERVICE_ACCOUNT,
    provider: 'AWS',
    department: 'Legacy Operations',
    lastActiveAt: new Date(Date.now() - 180 * 86_400_000),
    blastRadius: { accounts: 1, clusters: 0, secrets: 24, databases: 2 },
    attackPath: ['legacy-admin', 'AWS Administrator', 'Legacy Production Data'],
    grants: [
      ['AWS', 'aws:AdministratorAccess', 'aws:account:legacy-production', 'direct-policy'],
      ['AWS', 'credential:static', 'aws:iam:user/legacy-admin', 'access-key'],
      ['AWS', 'cloudtrail:StopLogging', 'aws:trail:legacy-production', 'direct-policy'],
      ['AWS', 's3:DeleteObject', 's3:audit-logs/legacy/*', 'direct-policy'],
    ],
  },
  {
    id: 'vault-bootstrap-admin',
    externalId: 'vault:vault-bootstrap-admin',
    displayName: 'vault-bootstrap-admin',
    email: null,
    type: IdentityType.SERVICE_ACCOUNT,
    provider: 'Vault',
    department: 'Security Platform',
    lastActiveAt: new Date(Date.now() - 12 * 86_400_000),
    blastRadius: { accounts: 2, clusters: 4, secrets: 240, databases: 5 },
    attackPath: ['Vault Bootstrap', 'Policy Author', 'Token Creator', 'Production Secrets'],
    grants: [
      ['Vault', 'vault:policy:write', 'vault:sys/policies/*', 'bootstrap-policy'],
      ['Vault', 'vault:token:create', 'vault:auth/token/create', 'bootstrap-policy'],
      ['Vault', 'vault:secrets:read', 'vault:production/*', 'bootstrap-policy'],
    ],
  },
  {
    id: 'database-backup-bot',
    externalId: 'workload:database-backup-bot',
    displayName: 'database-backup-bot',
    email: null,
    type: IdentityType.WORKLOAD,
    provider: 'Kubernetes',
    department: 'Data Platform',
    lastActiveAt: new Date(),
    blastRadius: { accounts: 2, clusters: 2, secrets: 18, databases: 12 },
    attackPath: [
      'Backup CronJob',
      'Production Database Dump',
      'External Transfer Bucket',
      'Customer Records',
    ],
    grants: [
      ['PostgreSQL', 'postgres:database:dump', 'postgres:production/customer', 'backup-role'],
      ['GCP', 'gcs:objects:create', 'gcs:external-transfer/database/*', 'workload-identity'],
      ['Kubernetes', 'k8s:secrets:read', 'k8s:namespace:data-platform', 'backup-service-account'],
    ],
  },
] as const;

async function seed(): Promise<void> {
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

  for (const demo of demoIdentities) {
    const { grants, ...identityData } = demo;
    const identity = await prisma.identity.upsert({
      where: { id: demo.id },
      update: identityData,
      create: identityData,
    });
    await prisma.grant.deleteMany({ where: { identityId: identity.id } });
    await prisma.grant.createMany({
      data: grants.map(([platform, permission, resource, source]) => ({
        identityId: identity.id,
        platform,
        permission,
        resource,
        source,
      })),
    });

    const stored = await prisma.identity.findUniqueOrThrow({
      where: { id: identity.id },
      include: { grants: true },
    });
    const matches = engine.evaluate(stored, rules);
    await prisma.identity.update({
      where: { id: identity.id },
      data: {
        riskScore: engine.calculateScore(matches),
        confidence: engine.calculateConfidence(matches),
      },
    });
    await prisma.finding.deleteMany({ where: { identityId: identity.id } });
    await prisma.finding.createMany({
      data: matches.map((match) => ({
        identityId: identity.id,
        ruleId: match.rule.id,
        severity: severityMap[match.rule.severity],
        confidence: match.rule.confidence,
        evidence: match.evidence,
      })),
    });
  }
}

seed()
  .then(() => prisma.$disconnect())
  .catch(async (error: unknown) => {
    console.error(error);
    await prisma.$disconnect();
    process.exitCode = 1;
  });
