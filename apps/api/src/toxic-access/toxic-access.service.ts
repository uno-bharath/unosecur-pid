import { BadRequestException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import {
  IdentityAccessSnapshot,
  RealtimeConnectorCoverage,
  RealtimeCoverageSummary,
  ToxicAccessEvaluation,
  ToxicAccessSimulation,
  ToxicAccessConflict,
} from './domain/toxic-access.types';
import { CustomToxicRuleService } from './custom-toxic-rule.service';
import { IDENTITY_ACCESS_SOURCE, IdentityAccessSource } from './ports/identity-access-source';
import { ToxicAccessCatalogService } from './toxic-access-catalog.service';
import { ToxicAccessEngineService } from './toxic-access-engine.service';

@Injectable()
export class ToxicAccessService {
  constructor(
    @Inject(IDENTITY_ACCESS_SOURCE)
    private readonly accessSource: IdentityAccessSource,
    private readonly catalog: ToxicAccessCatalogService,
    private readonly customRules: CustomToxicRuleService,
    private readonly engine: ToxicAccessEngineService,
  ) {}

  async evaluateIdentity(identityId: string): Promise<ToxicAccessEvaluation> {
    const identity = await this.requireIdentity(identityId);
    return this.toEvaluation(identity, this.engine.evaluate(identity, await this.getRules()));
  }

  async listConflictedIdentities(): Promise<ToxicAccessEvaluation[]> {
    const identities = await this.accessSource.listIdentities();
    const rules = await this.getRules();
    return identities
      .map((identity) => this.toEvaluation(identity, this.engine.evaluate(identity, rules)))
      .filter(({ conflicts }) => conflicts.length > 0)
      .sort((left, right) => right.summary.critical - left.summary.critical);
  }

  async simulate(
    identityId: string,
    removePermissions: string[],
    removeAssignments: string[] = [],
  ): Promise<ToxicAccessSimulation> {
    if (removePermissions.length === 0 && removeAssignments.length === 0) {
      throw new BadRequestException('Select at least one permission or role assignment to remove.');
    }
    const identity = await this.requireIdentity(identityId);
    const rules = await this.getRules();
    const current = this.engine.evaluate(identity, rules);
    const removed = new Set(removePermissions);
    const removedSources = new Set(removeAssignments);
    const projectedIdentity = {
      ...identity,
      grants: identity.grants.filter(
        ({ permission, assignment }) =>
          !removed.has(permission) && !removedSources.has(assignment.source),
      ),
    };
    const projected = this.engine.evaluate(projectedIdentity, rules);
    const projectedRuleIds = new Set(projected.map(({ ruleId }) => ruleId));
    const resolved = current.filter(({ ruleId }) => !projectedRuleIds.has(ruleId));
    const severityWeight = { critical: 4, high: 3, medium: 2, low: 1 } as const;
    const currentWeight = current.reduce(
      (total, conflict) => total + severityWeight[conflict.severity],
      0,
    );
    const projectedWeight = projected.reduce(
      (total, conflict) => total + severityWeight[conflict.severity],
      0,
    );
    const affectedPlatformsBefore = [...new Set(current.flatMap(({ platforms }) => platforms))];
    const affectedPlatformsAfter = [...new Set(projected.flatMap(({ platforms }) => platforms))];
    const protectedResources = [
      ...new Set(resolved.flatMap(({ evidence }) => evidence.map(({ resource }) => resource))),
    ];
    const controlsImproved = [...new Set(resolved.flatMap(({ mappings }) => mappings.nist))];
    const residualSeverity = (['critical', 'high', 'medium', 'low'] as const).find((severity) =>
      projected.some((conflict) => conflict.severity === severity),
    );
    const businessAccessPreservedPercent =
      identity.grants.length === 0
        ? 100
        : Math.round((projectedIdentity.grants.length / identity.grants.length) * 100);
    const riskReductionPercent =
      currentWeight === 0
        ? 0
        : Math.round(((currentWeight - projectedWeight) / currentWeight) * 100);

    return {
      identityId,
      removedPermissions: [...removed],
      removedAssignments: [...removedSources],
      currentConflictCount: current.length,
      projectedConflictCount: projected.length,
      resolvedConflicts: resolved.map(({ title }) => title),
      remainingConflicts: projected.map(({ title }) => title),
      preservedGrantCount: projectedIdentity.grants.length,
      businessAccessPreservedPercent,
      riskReductionPercent,
      resolvedCriticalConflicts: resolved.filter(({ severity }) => severity === 'critical').length,
      resolvedHighConflicts: resolved.filter(({ severity }) => severity === 'high').length,
      attackPathsDisrupted: resolved.length,
      protectedResources,
      controlsImproved,
      affectedPlatformsBefore,
      affectedPlatformsAfter,
      residualSeverity: residualSeverity ?? 'none',
      securityOutcomes: [
        `${resolved.length} verified toxic path${resolved.length === 1 ? '' : 's'} disrupted`,
        `${riskReductionPercent}% weighted conflict-risk reduction`,
        `${businessAccessPreservedPercent}% of existing business access retained`,
        protectedResources.length > 0
          ? `${protectedResources.length} exposed resource scope${protectedResources.length === 1 ? '' : 's'} protected`
          : 'No protected resource scope changed',
        controlsImproved.length > 0
          ? `${controlsImproved.length} mapped security control${controlsImproved.length === 1 ? '' : 's'} improved`
          : 'No mapped control improvement',
      ],
    };
  }

  async getRealtimeCoverage(): Promise<RealtimeCoverageSummary> {
    const evaluatedAt = new Date().toISOString();
    const identities = await this.accessSource.listIdentities();
    const rules = await this.getRules();
    const evaluations = identities.map((identity) => ({
      identity,
      conflicts: this.engine.evaluate(identity, rules),
    }));
    const connectorDefinitions: Array<
      Pick<RealtimeConnectorCoverage, 'platform' | 'domain' | 'syncMode' | 'dataSource'>
    > = [
      {
        platform: 'AWS',
        domain: 'CLOUD',
        syncMode: 'INCREMENTAL_POLL',
        dataSource: 'AWS IAM and CloudTrail adapter',
      },
      {
        platform: 'GCP',
        domain: 'CLOUD',
        syncMode: 'INCREMENTAL_POLL',
        dataSource: 'Cloud Asset Inventory adapter',
      },
      {
        platform: 'Azure',
        domain: 'CLOUD',
        syncMode: 'INCREMENTAL_POLL',
        dataSource: 'Azure Resource Graph adapter',
      },
      {
        platform: 'Entra ID',
        domain: 'IDENTITY',
        syncMode: 'API_SYNC',
        dataSource: 'Uno Entities / Microsoft Graph',
      },
      {
        platform: 'Kubernetes',
        domain: 'KUBERNETES',
        syncMode: 'EVENT_STREAM',
        dataSource: 'RBAC and audit-event adapter',
      },
      {
        platform: 'GitHub',
        domain: 'SUPPLY_CHAIN',
        syncMode: 'WEBHOOK',
        dataSource: 'GitHub App and audit-log adapter',
      },
      {
        platform: 'GitLab',
        domain: 'SUPPLY_CHAIN',
        syncMode: 'WEBHOOK',
        dataSource: 'GitLab audit-event adapter',
      },
      {
        platform: 'Jenkins',
        domain: 'SUPPLY_CHAIN',
        syncMode: 'API_SYNC',
        dataSource: 'Jenkins authorization adapter',
      },
      {
        platform: 'Vault',
        domain: 'SECRETS',
        syncMode: 'EVENT_STREAM',
        dataSource: 'Vault policy and audit adapter',
      },
      {
        platform: 'PostgreSQL',
        domain: 'DATA',
        syncMode: 'API_SYNC',
        dataSource: 'Database entitlement adapter',
      },
    ];
    const connectors = connectorDefinitions.map((definition, index) => {
      const platformEvaluations = evaluations.filter(({ identity }) =>
        identity.grants.some(({ platform }) => platform === definition.platform),
      );
      const grants = platformEvaluations.flatMap(({ identity }) =>
        identity.grants.filter(({ platform }) => platform === definition.platform),
      );
      const conflicts = evaluations.flatMap(({ conflicts }) =>
        conflicts.filter(({ platforms }) => platforms.includes(definition.platform)),
      );
      return {
        id: `connector-${index + 1}`,
        ...definition,
        status: grants.length > 0 ? ('CONNECTED' as const) : ('READY_TO_CONNECT' as const),
        identities: platformEvaluations.length,
        entitlements: grants.length,
        conflicts: conflicts.length,
        criticalConflicts: conflicts.filter(({ severity }) => severity === 'critical').length,
        evaluatedAt,
      };
    });
    const conflictingPermissions = new Set(
      evaluations.flatMap(({ conflicts }) =>
        conflicts.flatMap(({ evidence }) => evidence.map(({ permission }) => permission)),
      ),
    );
    const recentEntitlementEvents = evaluations
      .flatMap(({ identity }) =>
        identity.grants.map((grant) => ({
          id: grant.id,
          observedAt: evaluatedAt,
          platform: grant.platform,
          identityId: identity.identityId,
          displayName: identity.displayName,
          identityType: identity.type,
          permission: grant.permission,
          resource: grant.resource,
          assignment: grant.assignment.source,
          createsConflict: conflictingPermissions.has(grant.permission),
        })),
      )
      .sort((left, right) => Number(right.createsConflict) - Number(left.createsConflict))
      .slice(0, 12);

    return {
      evaluatedAt,
      evidenceMode: this.accessSource.sourceName.toLowerCase().includes('demo')
        ? 'DEMONSTRATION'
        : 'CONNECTED',
      evidenceSource: this.accessSource.sourceName,
      refreshIntervalSeconds: 15,
      connectedPlatforms: connectors.filter(({ status }) => status === 'CONNECTED').length,
      availablePlatforms: connectors.length,
      identitiesObserved: identities.length,
      entitlementsObserved: identities.reduce(
        (total, identity) => total + identity.grants.length,
        0,
      ),
      activeConflicts: evaluations.reduce(
        (total, evaluation) => total + evaluation.conflicts.length,
        0,
      ),
      connectors,
      recentEntitlementEvents,
    };
  }

  private async getRules() {
    return [...this.catalog.getRules(), ...(await this.customRules.getPublishedRules())];
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
      identityType: identity.type,
      provider: identity.provider,
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
