import { EffectiveGrant } from '../domain/toxic-access.types';

type GrantTuple = [platform: string, permission: string, resource: string, source: string];

/** Deterministic hash so the same identity always gets the same demo pack. */
export function hashIdentity(value: string): number {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) >>> 0;
  }
  return hash;
}

const AWS_ADMIN: GrantTuple[] = [
  ['AWS', 'aws:AdministratorAccess', 'aws:account:production', 'demo-enriched-policy'],
  ['AWS', 'iam:PassRole', 'aws:role:production-admin', 'demo-enriched-policy'],
  ['AWS', 'iam:CreateAccessKey', 'aws:iam:user/*', 'demo-enriched-policy'],
  ['AWS', 'cloudtrail:StopLogging', 'aws:trail:production', 'demo-enriched-policy'],
  ['AWS', 'cloudtrail:DeleteTrail', 'aws:trail:production', 'demo-enriched-policy'],
  ['AWS', 's3:GetObject', 's3:customer-data/*', 'demo-enriched-policy'],
  ['AWS', 's3:DeleteObject', 's3:audit-logs/*', 'demo-enriched-policy'],
  ['AWS', 'kms:CreateKey', 'aws:kms:production/*', 'demo-enriched-policy'],
  ['AWS', 'kms:Encrypt', 'aws:kms:production/*', 'demo-enriched-policy'],
  ['AWS', 'kms:ScheduleKeyDeletion', 'aws:kms:production/*', 'demo-enriched-policy'],
];

const K8S_ADMIN: GrantTuple[] = [
  ['Kubernetes', 'k8s:cluster-admin', 'k8s:cluster:prod-eks', 'demo-enriched-binding'],
  ['Kubernetes', 'k8s:bind', 'k8s:cluster:prod-eks', 'demo-enriched-binding'],
  ['Kubernetes', 'k8s:escalate', 'k8s:cluster:prod-eks', 'demo-enriched-binding'],
  ['Kubernetes', 'k8s:secrets:read', 'k8s:namespace:production', 'demo-enriched-binding'],
  ['Kubernetes', 'k8s:pods:create', 'k8s:namespace:production', 'demo-enriched-binding'],
];

const GITHUB_OWNER: GrantTuple[] = [
  ['GitHub', 'github:repo:admin', 'github:uno/prod-app', 'demo-enriched-owner'],
  ['GitHub', 'github:workflow:write', 'github:uno/prod-app', 'demo-enriched-owner'],
  ['GitHub', 'github:actions:secrets:read', 'github:uno/prod-app', 'demo-enriched-owner'],
  ['GitHub', 'github:branch-protection:write', 'github:uno/prod-app/main', 'demo-enriched-owner'],
];

const ENTRA_PRIV: GrantTuple[] = [
  ['Entra ID', 'identity:user:create', 'tenant:enterprise', 'demo-enriched-role'],
  ['Entra ID', 'identity:admin:assign', 'tenant:enterprise', 'demo-enriched-role'],
  ['Entra ID', 'entra:application:create', 'tenant:enterprise', 'demo-enriched-role'],
  ['Entra ID', 'entra:application:credentials:write', 'tenant:enterprise', 'demo-enriched-role'],
  ['Entra ID', 'entra:admin-consent:grant', 'tenant:enterprise', 'demo-enriched-role'],
];

const FINANCE_SOD: GrantTuple[] = [
  ['Entra ID', 'finance:vendor:create', 'erp:vendors', 'demo-enriched-finance'],
  ['Entra ID', 'finance:payment:approve', 'erp:payments', 'demo-enriched-finance'],
  ['AWS', 's3:GetObject', 's3:customer-data/finance/*', 'demo-enriched-finance'],
  ['AWS', 's3:PutObject', 's3:external-exchange/finance/*', 'demo-enriched-finance'],
];

const VAULT_ADMIN: GrantTuple[] = [
  ['Vault', 'vault:policy:write', 'vault:sys/policies/*', 'demo-enriched-vault'],
  ['Vault', 'vault:token:create', 'vault:auth/token/create', 'demo-enriched-vault'],
  ['Vault', 'vault:secrets:read', 'vault:production/*', 'demo-enriched-vault'],
];

const CROSS_PLATFORM: GrantTuple[] = [
  ...GITHUB_OWNER.slice(0, 3),
  ...AWS_ADMIN.slice(0, 3),
  ...K8S_ADMIN.slice(0, 3),
  ...VAULT_ADMIN.slice(2, 3),
];

const BACKUP_BOT: GrantTuple[] = [
  ['PostgreSQL', 'postgres:database:dump', 'postgres:production/customer', 'demo-enriched-backup'],
  ['GCP', 'gcs:objects:create', 'gcs:external-transfer/database/*', 'demo-enriched-backup'],
  ['Kubernetes', 'k8s:secrets:read', 'k8s:namespace:data-platform', 'demo-enriched-backup'],
];

const PROVIDER_PACKS: Record<string, GrantTuple[][]> = {
  AWS: [AWS_ADMIN, CROSS_PLATFORM, [...AWS_ADMIN.slice(0, 5), ...K8S_ADMIN.slice(0, 2)]],
  GCP: [
    [
      ['GCP', 'resourcemanager:projects:setIamPolicy', 'gcp:project:production', 'demo-enriched-iam'],
      ['GCP', 'iam:serviceAccounts:actAs', 'gcp:sa:prod-deployer', 'demo-enriched-iam'],
      ['GCP', 'gcs:objects:get', 'gcs:customer-data/*', 'demo-enriched-iam'],
      ['GCP', 'gcs:objects:create', 'gcs:external-transfer/*', 'demo-enriched-iam'],
      ...K8S_ADMIN.slice(0, 2),
    ],
    BACKUP_BOT,
    CROSS_PLATFORM,
  ],
  AZURE: [
    [
      ['Azure', 'azure:role:Owner', 'azure:subscription:production', 'demo-enriched-rbac'],
      ['Azure', 'azure:roleAssignments:write', 'azure:subscription:production', 'demo-enriched-rbac'],
      ['Entra ID', 'entra:application:credentials:write', 'tenant:enterprise', 'demo-enriched-rbac'],
      ['Entra ID', 'entra:admin-consent:grant', 'tenant:enterprise', 'demo-enriched-rbac'],
      ...VAULT_ADMIN.slice(2, 3),
    ],
    ENTRA_PRIV,
    CROSS_PLATFORM,
  ],
  'ENTRA ID': [ENTRA_PRIV, FINANCE_SOD, CROSS_PLATFORM],
  ENTRA: [ENTRA_PRIV, FINANCE_SOD, CROSS_PLATFORM],
  GITHUB: [GITHUB_OWNER, CROSS_PLATFORM, [...GITHUB_OWNER, ...AWS_ADMIN.slice(0, 2)]],
  KUBERNETES: [K8S_ADMIN, BACKUP_BOT, CROSS_PLATFORM],
  VAULT: [VAULT_ADMIN, [...VAULT_ADMIN, ...AWS_ADMIN.slice(0, 2)], CROSS_PLATFORM],
  'ACTIVE-DIRECTORY': [ENTRA_PRIV, FINANCE_SOD],
  'GOOGLE-WORKSPACE': [
    [
      ['Google Workspace', 'admin:users:create', 'workspace:domain', 'demo-enriched-admin'],
      ['Google Workspace', 'admin:roles:assign', 'workspace:domain', 'demo-enriched-admin'],
      ['GCP', 'resourcemanager:projects:setIamPolicy', 'gcp:project:shared', 'demo-enriched-admin'],
    ],
    FINANCE_SOD,
  ],
};

const DEFAULT_PACKS: GrantTuple[][] = [CROSS_PLATFORM, AWS_ADMIN, FINANCE_SOD, K8S_ADMIN, BACKUP_BOT];

function toGrants(identityId: string, displayName: string, tuples: GrantTuple[]): EffectiveGrant[] {
  return tuples.map(([platform, permission, resource, source], index) => ({
    id: `${identityId}:demo:${index}`,
    platform,
    permission,
    resource,
    assignment: {
      source,
      path: [displayName, source, permission, resource],
    },
  }));
}

const TOXIC_PERMISSION_HINT =
  /AdministratorAccess|PassRole|cluster-admin|secrets:read|StopLogging|vendor:create|payment:approve|identity:user:create|identity:admin:assign|vault:|github:repo:admin|entra:application|kms:ScheduleKeyDeletion|postgres:database:dump/i;

/**
 * When ClickHouse entities lack usable permission evidence, attach a deterministic
 * toxic grant pack so the demo MVP still surfaces full toxic-combination findings.
 */
export function enrichSparseGrants(
  identityId: string,
  displayName: string,
  provider: string,
  existing: EffectiveGrant[],
  minimumGrants = 2,
): EffectiveGrant[] {
  const hasToxicSignal = existing.some((grant) => TOXIC_PERMISSION_HINT.test(grant.permission));
  if (existing.length >= minimumGrants && hasToxicSignal) return existing;
  const key = provider.trim().toUpperCase();
  const packs = PROVIDER_PACKS[key] ?? PROVIDER_PACKS[provider] ?? DEFAULT_PACKS;
  const pack = packs[hashIdentity(identityId) % packs.length];
  const synthetic = toGrants(identityId, displayName, pack);
  const seen = new Set(existing.map((grant) => `${grant.platform}:${grant.permission}`));
  return [
    ...existing,
    ...synthetic.filter((grant) => !seen.has(`${grant.platform}:${grant.permission}`)),
  ];
}

export function attackPathForGrants(displayName: string, grants: EffectiveGrant[]): string[] {
  const platforms = [...new Set(grants.map((grant) => grant.platform))];
  const tip =
    grants.find((grant) => /secret|database|customer|production/i.test(grant.resource))?.resource ??
    grants.at(-1)?.resource ??
    'High-value resource';
  return [displayName, ...platforms.slice(0, 3), tip];
}
