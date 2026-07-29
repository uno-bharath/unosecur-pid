import { IdentityAccessSnapshot, ToxicCombinationRule } from './domain/toxic-access.types';
import { ToxicAccessEngineService } from './toxic-access-engine.service';

const rule: ToxicCombinationRule = {
  id: 'TAI-TEST-001',
  title: 'Cross-platform test conflict',
  description: 'A deterministic cross-platform test conflict.',
  category: 'CROSS_PLATFORM_CONTROL',
  severity: 'critical',
  businessImpact: 'The test identity can cross control planes.',
  remediation: 'Remove one side of the test conflict.',
  minimumPlatforms: 2,
  requirements: [
    { id: 'source', platform: 'GitHub', anyPermissions: ['repo:admin'] },
    { id: 'target', platform: 'AWS', anyPermissions: ['role:assume'] },
  ],
  mappings: { mitre: ['T1078'], nist: ['AC-5'] },
};

const identity: IdentityAccessSnapshot = {
  identityId: 'identity-1',
  displayName: 'Test Identity',
  type: 'HUMAN',
  provider: 'Entra ID',
  grants: [
    {
      id: 'grant-1',
      platform: 'GitHub',
      permission: 'repo:admin',
      resource: 'github:uno/app',
      assignment: { source: 'owner-team', path: ['Test Identity', 'owner-team', 'repo:admin'] },
    },
    {
      id: 'grant-2',
      platform: 'AWS',
      permission: 'role:assume',
      resource: 'aws:role/prod',
      assignment: {
        source: 'developer-role',
        path: ['Test Identity', 'developer-role', 'role:assume'],
      },
    },
  ],
};

describe('ToxicAccessEngineService', () => {
  const engine = new ToxicAccessEngineService();

  it('matches a complete cross-platform entitlement conflict with access-path evidence', () => {
    const conflicts = engine.evaluate(identity, [rule]);

    expect(conflicts).toHaveLength(1);
    expect(conflicts[0].platforms).toEqual(['AWS', 'GitHub']);
    expect(conflicts[0].evidence[0].accessPath).toContain('owner-team');
  });

  it('does not match when one required control plane is absent', () => {
    expect(engine.evaluate({ ...identity, grants: identity.grants.slice(0, 1) }, [rule])).toEqual(
      [],
    );
  });

  it('supports wildcard resource constraints', () => {
    const resourceRule: ToxicCombinationRule = {
      ...rule,
      requirements: [
        { ...rule.requirements[0], resourcePattern: 'github:uno/*' },
        rule.requirements[1],
      ],
    };

    expect(engine.evaluate(identity, [resourceRule])).toHaveLength(1);
  });
});
