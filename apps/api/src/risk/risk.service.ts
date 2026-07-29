import { Injectable, NotFoundException } from '@nestjs/common';
import { RiskEngineService } from './risk-engine.service';
import { RiskRepository } from './risk.repository';
import { RuleCatalogService } from './rule-catalog.service';
import { RiskSimulation, RiskSummary, ToxicIdentity } from './risk.types';

@Injectable()
export class RiskService {
  constructor(
    private readonly repository: RiskRepository,
    private readonly catalog: RuleCatalogService,
    private readonly engine: RiskEngineService,
  ) {}

  async scan(): Promise<{ identitiesEvaluated: number; findingsCreated: number }> {
    const rules = this.catalog.getRules();
    await this.repository.syncRules(rules);
    const identities = await this.repository.getScannableIdentities();

    let findingsCreated = 0;
    for (const identity of identities) {
      const matches = this.engine.evaluate(identity, rules);
      findingsCreated += matches.length;
      await this.repository.saveEvaluation(
        identity.id,
        this.engine.calculateScore(matches),
        this.engine.calculateConfidence(matches),
        matches,
      );
    }

    return { identitiesEvaluated: identities.length, findingsCreated };
  }

  async getSummary(): Promise<RiskSummary> {
    const identities = await this.repository.getToxicIdentities();
    const findings = await this.repository.getFindingCount();
    const platformCoverage = [...new Set(identities.flatMap(({ platforms }) => platforms))].sort();
    const criticalIdentities = identities.filter(({ riskScore }) => riskScore >= 80).length;
    const enterpriseRiskScore =
      identities.length === 0
        ? 0
        : Math.round(
            identities.reduce((total, identity) => total + identity.riskScore, 0) /
              identities.length,
          );

    return {
      enterpriseRiskScore,
      identitiesScanned: identities.length,
      criticalIdentities,
      attackPaths: identities.filter(({ attackPath }) => attackPath.length > 1).length,
      findings,
      platformCoverage,
      topIdentities: identities.slice(0, 5),
    };
  }

  getIdentities(): Promise<ToxicIdentity[]> {
    return this.repository.getToxicIdentities();
  }

  async getIdentity(id: string): Promise<ToxicIdentity> {
    const identity = (await this.repository.getToxicIdentities()).find(
      (candidate) => candidate.id === id,
    );
    if (!identity) {
      throw new NotFoundException(`Identity ${id} was not found`);
    }
    return identity;
  }

  async simulate(id: string, removePermissions: string[]): Promise<RiskSimulation> {
    const rules = this.catalog.getRules();
    const identity = (await this.repository.getScannableIdentities()).find(
      (candidate) => candidate.id === id,
    );
    if (!identity) {
      throw new NotFoundException(`Identity ${id} was not found`);
    }

    const currentMatches = this.engine.evaluate(identity, rules);
    const removed = new Set(removePermissions);
    const projectedMatches = this.engine.evaluate(
      {
        ...identity,
        grants: identity.grants.filter(({ permission }) => !removed.has(permission)),
      },
      rules,
    );
    const projectedRuleIds = new Set(projectedMatches.map(({ rule }) => rule.id));
    const currentScore = this.engine.calculateScore(currentMatches);
    const projectedScore = this.engine.calculateScore(projectedMatches);

    return {
      identityId: id,
      currentScore,
      projectedScore,
      scoreReduction: currentScore - projectedScore,
      removedPermissions: [...removed],
      resolvedFindings: currentMatches
        .filter(({ rule }) => !projectedRuleIds.has(rule.id))
        .map(({ rule }) => rule.title),
      remainingFindings: projectedMatches.map(({ rule }) => rule.title),
    };
  }
}
