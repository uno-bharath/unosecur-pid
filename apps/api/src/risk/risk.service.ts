import { Injectable, NotFoundException } from '@nestjs/common';
import { RiskEngineService } from './risk-engine.service';
import { RiskRepository } from './risk.repository';
import { RuleCatalogService } from './rule-catalog.service';
import { RiskSummary, ToxicIdentity } from './risk.types';

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
}
