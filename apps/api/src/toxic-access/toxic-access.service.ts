import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import {
  IdentityAccessSnapshot,
  ToxicAccessEvaluation,
  ToxicAccessSimulation,
  ToxicAccessConflict,
} from './domain/toxic-access.types';
import { IDENTITY_ACCESS_SOURCE, IdentityAccessSource } from './ports/identity-access-source';
import { ToxicAccessCatalogService } from './toxic-access-catalog.service';
import { ToxicAccessEngineService } from './toxic-access-engine.service';

@Injectable()
export class ToxicAccessService {
  constructor(
    @Inject(IDENTITY_ACCESS_SOURCE)
    private readonly accessSource: IdentityAccessSource,
    private readonly catalog: ToxicAccessCatalogService,
    private readonly engine: ToxicAccessEngineService,
  ) {}

  async evaluateIdentity(identityId: string): Promise<ToxicAccessEvaluation> {
    const identity = await this.requireIdentity(identityId);
    return this.toEvaluation(identity, this.engine.evaluate(identity, this.catalog.getRules()));
  }

  async listConflictedIdentities(): Promise<ToxicAccessEvaluation[]> {
    const identities = await this.accessSource.listIdentities();
    return identities
      .map((identity) =>
        this.toEvaluation(identity, this.engine.evaluate(identity, this.catalog.getRules())),
      )
      .filter(({ conflicts }) => conflicts.length > 0)
      .sort((left, right) => right.summary.critical - left.summary.critical);
  }

  async simulate(identityId: string, removePermissions: string[]): Promise<ToxicAccessSimulation> {
    const identity = await this.requireIdentity(identityId);
    const rules = this.catalog.getRules();
    const current = this.engine.evaluate(identity, rules);
    const removed = new Set(removePermissions);
    const projectedIdentity = {
      ...identity,
      grants: identity.grants.filter(({ permission }) => !removed.has(permission)),
    };
    const projected = this.engine.evaluate(projectedIdentity, rules);
    const projectedRuleIds = new Set(projected.map(({ ruleId }) => ruleId));

    return {
      identityId,
      removedPermissions: [...removed],
      currentConflictCount: current.length,
      projectedConflictCount: projected.length,
      resolvedConflicts: current
        .filter(({ ruleId }) => !projectedRuleIds.has(ruleId))
        .map(({ title }) => title),
      remainingConflicts: projected.map(({ title }) => title),
      preservedGrantCount: projectedIdentity.grants.length,
    };
  }

  private async requireIdentity(identityId: string): Promise<IdentityAccessSnapshot> {
    const identity = await this.accessSource.getIdentity(identityId);
    if (!identity) throw new NotFoundException(`Identity ${identityId} was not found`);
    return identity;
  }

  private toEvaluation(
    identity: IdentityAccessSnapshot,
    conflicts: ToxicAccessConflict[],
  ): ToxicAccessEvaluation {
    return {
      identityId: identity.identityId,
      displayName: identity.displayName,
      evaluatedAt: new Date().toISOString(),
      source: this.accessSource.sourceName,
      conflicts,
      summary: {
        total: conflicts.length,
        critical: conflicts.filter(({ severity }) => severity === 'critical').length,
        high: conflicts.filter(({ severity }) => severity === 'high').length,
        affectedPlatforms: [...new Set(conflicts.flatMap(({ platforms }) => platforms))].sort(),
      },
    };
  }
}
