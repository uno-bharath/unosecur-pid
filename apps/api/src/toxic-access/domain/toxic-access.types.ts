export type AccessIdentityType = 'HUMAN' | 'SERVICE_ACCOUNT' | 'WORKLOAD';
export type ConflictSeverity = 'critical' | 'high' | 'medium' | 'low';
export type ConflictCategory =
  | 'SEGREGATION_OF_DUTIES'
  | 'CROSS_PLATFORM_CONTROL'
  | 'SUPPLY_CHAIN_PIVOT'
  | 'DATA_CONTROL_CONFLICT';

export interface EffectiveGrant {
  id: string;
  platform: string;
  permission: string;
  resource: string;
  assignment: {
    source: string;
    path: string[];
  };
}

export interface IdentityAccessSnapshot {
  identityId: string;
  displayName: string;
  type: AccessIdentityType;
  provider: string;
  grants: EffectiveGrant[];
}

export interface EntitlementRequirement {
  id: string;
  platform?: string;
  anyPermissions: string[];
  resourcePattern?: string;
}

export interface ToxicCombinationRule {
  id: string;
  title: string;
  description: string;
  category: ConflictCategory;
  severity: ConflictSeverity;
  businessImpact: string;
  remediation: string;
  requirements: EntitlementRequirement[];
  identityTypes?: AccessIdentityType[];
  minimumPlatforms?: number;
  mappings: {
    mitre: string[];
    nist: string[];
  };
}

export interface MatchedEntitlement {
  requirementId: string;
  grantId: string;
  platform: string;
  permission: string;
  resource: string;
  accessPath: string[];
}

export interface ToxicAccessConflict {
  ruleId: string;
  title: string;
  category: ConflictCategory;
  severity: ConflictSeverity;
  businessImpact: string;
  remediation: string;
  platforms: string[];
  evidence: MatchedEntitlement[];
  mappings: ToxicCombinationRule['mappings'];
}

export interface ToxicAccessEvaluation {
  identityId: string;
  displayName: string;
  evaluatedAt: string;
  source: string;
  conflicts: ToxicAccessConflict[];
  summary: {
    total: number;
    critical: number;
    high: number;
    affectedPlatforms: string[];
  };
}

export interface ToxicAccessSimulation {
  identityId: string;
  removedPermissions: string[];
  currentConflictCount: number;
  projectedConflictCount: number;
  resolvedConflicts: string[];
  remainingConflicts: string[];
  preservedGrantCount: number;
}
