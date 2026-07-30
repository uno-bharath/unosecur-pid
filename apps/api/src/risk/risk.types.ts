export type RiskSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface BlastRadius {
  accounts: number;
  clusters: number;
  secrets: number;
  databases: number;
}

export interface RuleMatching {
  allPermissions?: string[];
  anyPermissions?: string[];
  minPlatforms?: number;
  identityTypes?: Array<'HUMAN' | 'SERVICE_ACCOUNT' | 'WORKLOAD'>;
  dormantDays?: number;
}

export interface RiskRuleDefinition {
  id: string;
  title: string;
  platform: string;
  category: string;
  severity: RiskSeverity;
  description: string;
  businessImpact: string;
  remediation: string;
  mitreMappings: string[];
  nistMappings: string[];
  riskWeight: number;
  confidence: number;
  matching: RuleMatching;
}

export interface EvaluatedGrant {
  platform: string;
  permission: string;
  resource: string;
  source: string;
}

export interface EvaluatedIdentity {
  type: 'HUMAN' | 'SERVICE_ACCOUNT' | 'WORKLOAD';
  lastActiveAt: Date | null;
  grants: EvaluatedGrant[];
}

export interface RuleMatch {
  rule: RiskRuleDefinition;
  evidence: {
    matchedPermissions: string[];
    platforms: string[];
    dormantDays?: number;
  };
}

export interface RiskFactor {
  ruleId: string;
  title: string;
  platform: string;
  severity: RiskSeverity;
  justification: string;
  businessImpact: string;
  remediation: string;
  mitre: string;
  nist: string;
  evidence: Record<string, unknown>;
}

export interface ToxicIdentity {
  id: string;
  name: string;
  type: 'Human' | 'Workload' | 'Service account';
  department: string;
  riskScore: number;
  confidence: number;
  platforms: string[];
  blastRadius: BlastRadius;
  factors: RiskFactor[];
  attackPath: string[];
}

export interface RiskSummary {
  enterpriseRiskScore: number;
  identitiesScanned: number;
  criticalIdentities: number;
  attackPaths: number;
  findings: number;
  platformCoverage: string[];
  topIdentities: ToxicIdentity[];
}

export interface PostureTrendPoint {
  date: string;
  toxicIdentities: number;
  totalConflicts: number;
  criticalConflicts: number;
  newConflicts: number;
  remediatedConflicts: number;
  attackPaths: number;
}

export interface ExecutivePostureTrend {
  periodDays: number;
  points: PostureTrendPoint[];
  summary: {
    toxicIdentityChange: number;
    toxicIdentityChangePercent: number;
    conflictsRemediated: number;
    newConflicts: number;
    netConflictChange: number;
    remediationEfficiency: number;
  };
}

export interface RiskSimulation {
  identityId: string;
  currentScore: number;
  projectedScore: number;
  scoreReduction: number;
  removedPermissions: string[];
  resolvedFindings: string[];
  remainingFindings: string[];
}
