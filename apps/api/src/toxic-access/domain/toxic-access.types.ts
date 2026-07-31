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
  identityType: AccessIdentityType;
  provider: string;
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
  removedAssignments: string[];
  currentConflictCount: number;
  projectedConflictCount: number;
  resolvedConflicts: string[];
  remainingConflicts: string[];
  preservedGrantCount: number;
  businessAccessPreservedPercent: number;
  riskReductionPercent: number;
  resolvedCriticalConflicts: number;
  resolvedHighConflicts: number;
  attackPathsDisrupted: number;
  protectedResources: string[];
  controlsImproved: string[];
  affectedPlatformsBefore: string[];
  affectedPlatformsAfter: string[];
  residualSeverity: ConflictSeverity | 'none';
  securityOutcomes: string[];
}

export interface RealtimeConnectorCoverage {
  id: string;
  platform: string;
  domain: 'CLOUD' | 'IDENTITY' | 'SUPPLY_CHAIN' | 'KUBERNETES' | 'SECRETS' | 'DATA';
  status: 'CONNECTED' | 'READY_TO_CONNECT';
  syncMode: 'EVENT_STREAM' | 'INCREMENTAL_POLL' | 'WEBHOOK' | 'API_SYNC';
  identities: number;
  entitlements: number;
  conflicts: number;
  criticalConflicts: number;
  evaluatedAt: string;
  dataSource: string;
}

export interface RealtimeEntitlementEvent {
  id: string;
  observedAt: string;
  platform: string;
  identityId: string;
  displayName: string;
  identityType: AccessIdentityType;
  permission: string;
  resource: string;
  assignment: string;
  createsConflict: boolean;
}

export interface RealtimeCoverageSummary {
  evaluatedAt: string;
  evidenceMode: 'DEMONSTRATION' | 'CONNECTED';
  evidenceSource: string;
  refreshIntervalSeconds: number;
  connectedPlatforms: number;
  availablePlatforms: number;
  identitiesObserved: number;
  entitlementsObserved: number;
  activeConflicts: number;
  connectors: RealtimeConnectorCoverage[];
  recentEntitlementEvents: RealtimeEntitlementEvent[];
}
