import { Injectable } from '@nestjs/common';
import { Prisma, Severity } from '@prisma/client';
import { PrismaService } from '../database/prisma.service';
import {
  BlastRadius,
  RiskRuleDefinition,
  RiskSeverity,
  RuleMatch,
  ToxicIdentity,
} from './risk.types';

const severityToPrisma: Record<RiskSeverity, Severity> = {
  critical: Severity.CRITICAL,
  high: Severity.HIGH,
  medium: Severity.MEDIUM,
  low: Severity.LOW,
};

const severityFromPrisma: Record<Severity, RiskSeverity> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
};

@Injectable()
export class RiskRepository {
  constructor(private readonly prisma: PrismaService) {}

  async syncRules(rules: readonly RiskRuleDefinition[]): Promise<void> {
    await this.prisma.$transaction(
      rules.map((rule) =>
        this.prisma.riskRule.upsert({
          where: { id: rule.id },
          update: {
            title: rule.title,
            platform: rule.platform,
            category: rule.category,
            severity: severityToPrisma[rule.severity],
            description: rule.description,
            businessImpact: rule.businessImpact,
            remediation: rule.remediation,
            mitreMappings: rule.mitreMappings,
            nistMappings: rule.nistMappings,
            matching: rule.matching as Prisma.InputJsonValue,
            riskWeight: rule.riskWeight,
            confidence: rule.confidence,
          },
          create: {
            id: rule.id,
            title: rule.title,
            platform: rule.platform,
            category: rule.category,
            severity: severityToPrisma[rule.severity],
            description: rule.description,
            businessImpact: rule.businessImpact,
            remediation: rule.remediation,
            mitreMappings: rule.mitreMappings,
            nistMappings: rule.nistMappings,
            matching: rule.matching as Prisma.InputJsonValue,
            riskWeight: rule.riskWeight,
            confidence: rule.confidence,
          },
        }),
      ),
    );
  }

  getScannableIdentities() {
    return this.prisma.identity.findMany({ include: { grants: true } });
  }

  async saveEvaluation(
    identityId: string,
    score: number,
    confidence: number,
    matches: readonly RuleMatch[],
  ): Promise<void> {
    await this.prisma.$transaction([
      this.prisma.identity.update({
        where: { id: identityId },
        data: { riskScore: score, confidence },
      }),
      this.prisma.finding.deleteMany({ where: { identityId } }),
      this.prisma.finding.createMany({
        data: matches.map((match) => ({
          identityId,
          ruleId: match.rule.id,
          severity: severityToPrisma[match.rule.severity],
          confidence: match.rule.confidence,
          evidence: match.evidence,
        })),
      }),
    ]);
  }

  async getToxicIdentities(limit?: number): Promise<ToxicIdentity[]> {
    const identities = await this.prisma.identity.findMany({
      orderBy: { riskScore: 'desc' },
      ...(limit ? { take: limit } : {}),
      include: {
        grants: true,
        findings: {
          orderBy: { severity: 'desc' },
          include: { rule: true },
        },
      },
    });

    return identities.map((identity) => ({
      id: identity.id,
      name: identity.displayName,
      type:
        identity.type === 'HUMAN'
          ? 'Human'
          : identity.type === 'WORKLOAD'
            ? 'Workload'
            : 'Service account',
      department: identity.department,
      riskScore: identity.riskScore,
      confidence: identity.confidence,
      platforms: [...new Set(identity.grants.map(({ platform }) => platform))],
      blastRadius: this.parseBlastRadius(identity.blastRadius),
      attackPath: identity.attackPath,
      factors: identity.findings.map((finding) => ({
        ruleId: finding.ruleId,
        title: finding.rule.title,
        platform: finding.rule.platform,
        severity: severityFromPrisma[finding.severity],
        justification: finding.rule.description,
        businessImpact: finding.rule.businessImpact,
        remediation: finding.rule.remediation,
        mitre: finding.rule.mitreMappings.join(', '),
        nist: finding.rule.nistMappings.join(', '),
        evidence: finding.evidence as Record<string, unknown>,
      })),
    }));
  }

  async getFindingCount(): Promise<number> {
    return this.prisma.finding.count();
  }

  private parseBlastRadius(value: Prisma.JsonValue): BlastRadius {
    const radius = value as Record<string, unknown>;
    return {
      accounts: Number(radius.accounts ?? 0),
      clusters: Number(radius.clusters ?? 0),
      secrets: Number(radius.secrets ?? 0),
      databases: Number(radius.databases ?? 0),
    };
  }
}
