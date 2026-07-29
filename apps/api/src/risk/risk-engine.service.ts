import { Injectable } from '@nestjs/common';
import { EvaluatedIdentity, RiskRuleDefinition, RuleMatch } from './risk.types';

const severityBonus: Record<RiskRuleDefinition['severity'], number> = {
  critical: 10,
  high: 6,
  medium: 3,
  low: 1,
};

@Injectable()
export class RiskEngineService {
  evaluate(identity: EvaluatedIdentity, rules: readonly RiskRuleDefinition[]): RuleMatch[] {
    return rules.flatMap((rule) => {
      const match = this.matchRule(identity, rule);
      return match ? [match] : [];
    });
  }

  calculateScore(matches: readonly RuleMatch[]): number {
    const weighted = matches.reduce(
      (total, match) => total + match.rule.riskWeight + severityBonus[match.rule.severity],
      0,
    );
    const diversityBonus =
      Math.max(0, new Set(matches.map(({ rule }) => rule.platform)).size - 1) * 4;
    return Math.min(100, weighted + diversityBonus);
  }

  calculateConfidence(matches: readonly RuleMatch[]): number {
    if (matches.length === 0) return 0;
    return Math.round(
      matches.reduce((total, match) => total + match.rule.confidence, 0) / matches.length,
    );
  }

  private matchRule(identity: EvaluatedIdentity, rule: RiskRuleDefinition): RuleMatch | null {
    const permissions = new Set(identity.grants.map(({ permission }) => permission));
    const platforms = [...new Set(identity.grants.map(({ platform }) => platform))];
    const { matching } = rule;
    const matchedPermissions = [
      ...(matching.allPermissions ?? []),
      ...(matching.anyPermissions ?? []).filter((permission) => permissions.has(permission)),
    ];

    if (matching.identityTypes && !matching.identityTypes.includes(identity.type)) return null;
    if (
      matching.allPermissions &&
      !matching.allPermissions.every((permission) => permissions.has(permission))
    ) {
      return null;
    }
    if (
      matching.anyPermissions &&
      !matching.anyPermissions.some((permission) => permissions.has(permission))
    ) {
      return null;
    }
    if (matching.minPlatforms && platforms.length < matching.minPlatforms) return null;

    let dormantDays: number | undefined;
    if (matching.dormantDays) {
      if (!identity.lastActiveAt) return null;
      dormantDays = Math.floor((Date.now() - identity.lastActiveAt.getTime()) / 86_400_000);
      if (dormantDays < matching.dormantDays) return null;
    }

    return {
      rule,
      evidence: { matchedPermissions, platforms, ...(dormantDays ? { dormantDays } : {}) },
    };
  }
}
