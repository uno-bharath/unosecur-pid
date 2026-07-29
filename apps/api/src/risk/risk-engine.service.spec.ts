import { RiskEngineService } from './risk-engine.service';
import { EvaluatedIdentity, RiskRuleDefinition } from './risk.types';

const rule = (overrides: Partial<RiskRuleDefinition> = {}): RiskRuleDefinition => ({
  id: 'TEST-001',
  title: 'Test toxic combination',
  platform: 'AWS',
  category: 'Privilege escalation',
  severity: 'critical',
  description: 'A deterministic test risk rule.',
  businessImpact: 'A test identity can gain additional access.',
  remediation: 'Remove one permission from the combination.',
  mitreMappings: ['T1548'],
  nistMappings: ['AC-6'],
  riskWeight: 20,
  confidence: 95,
  matching: { allPermissions: ['iam:PassRole', 'lambda:CreateFunction'] },
  ...overrides,
});

const identity = (permissions: string[]): EvaluatedIdentity => ({
  type: 'HUMAN',
  lastActiveAt: new Date(),
  grants: permissions.map((permission) => ({
    platform: 'AWS',
    permission,
    resource: '*',
    source: 'test',
  })),
});

describe('RiskEngineService', () => {
  const engine = new RiskEngineService();

  it('matches a complete toxic permission combination', () => {
    const matches = engine.evaluate(identity(['iam:PassRole', 'lambda:CreateFunction']), [rule()]);
    expect(matches).toHaveLength(1);
    expect(matches[0].evidence.matchedPermissions).toHaveLength(2);
  });

  it('does not match an incomplete combination', () => {
    expect(engine.evaluate(identity(['iam:PassRole']), [rule()])).toHaveLength(0);
  });

  it('caps the explainable score at one hundred', () => {
    const matches = engine.evaluate(identity(['iam:PassRole', 'lambda:CreateFunction']), [
      rule({ riskWeight: 100 }),
      rule({ id: 'TEST-002', riskWeight: 100 }),
    ]);
    expect(engine.calculateScore(matches)).toBe(100);
  });

  it('matches dormant privileged access only after the threshold', () => {
    const dormant = identity(['aws:AdministratorAccess']);
    dormant.lastActiveAt = new Date(Date.now() - 120 * 86_400_000);
    const matches = engine.evaluate(dormant, [
      rule({
        matching: {
          anyPermissions: ['aws:AdministratorAccess'],
          dormantDays: 90,
        },
      }),
    ]);
    expect(matches[0].evidence.dormantDays).toBeGreaterThanOrEqual(120);
  });
});
