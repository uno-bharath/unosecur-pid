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
      ['GitHub', 'github:actions:secrets:read', 'github:uno/prod-app', 'workflow'],
      ['AWS', 'iam:PassRole', 'aws:role:prod-deployer', 'access-key'],
      ['AWS', 'lambda:CreateFunction', 'aws:account:production', 'access-key'],
      ['Kubernetes', 'k8s:cluster-admin', 'k8s:cluster:prod-eks', 'deployment-role'],
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
      ['AWS', 's3:GetObject', 's3:finance-reports', 'finance-data-reader'],
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
