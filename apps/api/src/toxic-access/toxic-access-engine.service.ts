import { Injectable } from '@nestjs/common';
import {
  EffectiveGrant,
  IdentityAccessSnapshot,
  MatchedEntitlement,
  ToxicAccessConflict,
  ToxicCombinationRule,
} from './domain/toxic-access.types';

@Injectable()
export class ToxicAccessEngineService {
  evaluate(
    identity: IdentityAccessSnapshot,
    rules: readonly ToxicCombinationRule[],
  ): ToxicAccessConflict[] {
    return rules.flatMap((rule) => {
      const conflict = this.matchRule(identity, rule);
      return conflict ? [conflict] : [];
    });
  }

  private matchRule(
    identity: IdentityAccessSnapshot,
    rule: ToxicCombinationRule,
  ): ToxicAccessConflict | null {
    if (rule.identityTypes && !rule.identityTypes.includes(identity.type)) return null;

    const evidence = rule.requirements.flatMap((requirement) => {
      const match = identity.grants.find(
        (grant) =>
          (!requirement.platform || grant.platform === requirement.platform) &&
          requirement.anyPermissions.includes(grant.permission) &&
          this.matchesResource(grant, requirement.resourcePattern),
      );
      return match
        ? [
            {
              requirementId: requirement.id,
              grantId: match.id,
              platform: match.platform,
              permission: match.permission,
              resource: match.resource,
              accessPath: match.assignment.path,
            } satisfies MatchedEntitlement,
          ]
        : [];
    });

    if (evidence.length !== rule.requirements.length) return null;
    const platforms = [...new Set(evidence.map(({ platform }) => platform))].sort();
    if (rule.minimumPlatforms && platforms.length < rule.minimumPlatforms) return null;

    return {
      ruleId: rule.id,
      title: rule.title,
      category: rule.category,
      severity: rule.severity,
      businessImpact: rule.businessImpact,
      remediation: rule.remediation,
      platforms,
      evidence,
      mappings: rule.mappings,
    };
  }

  private matchesResource(grant: EffectiveGrant, resourcePattern?: string): boolean {
    if (!resourcePattern) return true;
    const escaped = resourcePattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replaceAll('*', '.*');
    return new RegExp(`^${escaped}$`, 'i').test(grant.resource);
  }
}
