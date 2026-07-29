import { Injectable, NotFoundException } from '@nestjs/common';

export interface RiskFactor {
  ruleId: string;
  title: string;
  platform: string;
  severity: 'critical' | 'high' | 'medium';
  justification: string;
  remediation: string;
  mitre: string;
}

export interface ToxicIdentity {
  id: string;
  name: string;
  type: 'Human' | 'Workload';
  department: string;
  riskScore: number;
  confidence: number;
  platforms: string[];
  blastRadius: { accounts: number; clusters: number; secrets: number; databases: number };
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

const identities: ToxicIdentity[] = [
  {
    id: 'john-smith',
    name: 'John Smith',
    type: 'Human',
    department: 'Platform Engineering',
    riskScore: 97,
    confidence: 96,
    platforms: ['AWS', 'Kubernetes', 'GitHub', 'Vault'],
    blastRadius: { accounts: 8, clusters: 12, secrets: 180, databases: 4 },
    factors: [
      {
        ruleId: 'CROSS-CLOUD-001',
        title: 'Cross-control-plane administrator',
        platform: 'Identity',
        severity: 'critical',
        justification:
          'A single compromise can control source, deployment, cloud, and secrets planes.',
        remediation: 'Split GitHub, cloud, cluster, and secrets administration into JIT roles.',
        mitre: 'T1078 Valid Accounts',
      },
      {
        ruleId: 'AWS-IAM-PRIVESC-004',
        title: 'PassRole with workload creation',
        platform: 'AWS',
        severity: 'critical',
        justification: 'iam:PassRole plus Lambda creation enables privilege escalation.',
        remediation: 'Constrain PassRole resources and enforce permission boundaries.',
        mitre: 'T1098 Account Manipulation',
      },
      {
        ruleId: 'K8S-RBAC-003',
        title: 'RBAC bind and escalate permissions',
        platform: 'Kubernetes',
        severity: 'critical',
        justification: 'The identity can grant privileges beyond its current effective access.',
        remediation: 'Remove bind/escalate and use a controlled cluster-role approval workflow.',
        mitre: 'T1548 Abuse Elevation Control Mechanism',
      },
    ],
    attackPath: [
      'John Smith',
      'GitHub Owner',
      'Actions Secret',
      'AWS Production Role',
      'EKS Admin',
      'Vault Secrets',
      'Customer Database',
    ],
  },
  {
    id: 'deploy-bot',
    name: 'prod-deploy-bot',
    type: 'Workload',
    department: 'Engineering',
    riskScore: 91,
    confidence: 93,
    platforms: ['GitHub', 'AWS', 'Kubernetes'],
    blastRadius: { accounts: 3, clusters: 7, secrets: 64, databases: 2 },
    factors: [
      {
        ruleId: 'MACHINE-ID-002',
        title: 'Long-lived workload credential',
        platform: 'Identity',
        severity: 'high',
        justification: 'A non-expiring credential bridges CI/CD and production.',
        remediation: 'Replace static credentials with OIDC workload federation.',
        mitre: 'T1552 Unsecured Credentials',
      },
    ],
    attackPath: ['GitHub Actions', 'Static AWS Key', 'Production Role', 'EKS Cluster Admin'],
  },
  {
    id: 'maya-patel',
    name: 'Maya Patel',
    type: 'Human',
    department: 'Finance',
    riskScore: 84,
    confidence: 91,
    platforms: ['Entra ID', 'AWS'],
    blastRadius: { accounts: 2, clusters: 0, secrets: 12, databases: 3 },
    factors: [
      {
        ruleId: 'SOD-FIN-001',
        title: 'Create vendor and approve payment',
        platform: 'Identity',
        severity: 'critical',
        justification: 'The combination bypasses segregation of duties and enables vendor fraud.',
        remediation: 'Separate vendor creation and payment approval with dual control.',
        mitre: 'T1078 Valid Accounts',
      },
    ],
    attackPath: ['Maya Patel', 'Finance Operator', 'Create Vendor', 'Approve Payment'],
  },
];

@Injectable()
export class RiskService {
  getSummary(): RiskSummary {
    return {
      enterpriseRiskScore: 86,
      identitiesScanned: 12_480,
      criticalIdentities: 18,
      attackPaths: 42,
      findings: 327,
      platformCoverage: ['AWS', 'Azure', 'GCP', 'Kubernetes', 'GitHub', 'Entra ID'],
      topIdentities: identities,
    };
  }

  getIdentities(): ToxicIdentity[] {
    return [...identities].sort((left, right) => right.riskScore - left.riskScore);
  }

  getIdentity(id: string): ToxicIdentity {
    const identity = identities.find((candidate) => candidate.id === id);
    if (!identity) {
      throw new NotFoundException(`Identity ${id} was not found`);
    }
    return identity;
  }
}
