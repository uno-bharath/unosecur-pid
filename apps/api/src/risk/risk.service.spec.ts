import { RiskEngineService } from './risk-engine.service';
import { RiskRepository } from './risk.repository';
import { RiskService } from './risk.service';
import { RiskRuleDefinition } from './risk.types';
import { RuleCatalogService } from './rule-catalog.service';

describe('RiskService what-if simulation', () => {
  const rules: RiskRuleDefinition[] = [
    {
      id: 'TEST-SOD-001',
      title: 'Create and approve',
      platform: 'Identity',
      category: 'Separation of duties',
      severity: 'critical',
      description: 'Conflicting permissions',
      businessImpact: 'Fraud',
      remediation: 'Separate duties',
      mitreMappings: ['T1078'],
      nistMappings: ['AC-5'],
      riskWeight: 25,
      confidence: 99,
      matching: { allPermissions: ['resource:create', 'resource:approve'] },
    },
  ];
  const identity = {
    id: 'test-user',
    type: 'HUMAN' as const,
    lastActiveAt: new Date(),
    grants: [
      {
        platform: 'Identity',
        permission: 'resource:create',
        resource: 'test',
        source: 'role',
      },
      {
        platform: 'Identity',
        permission: 'resource:approve',
        resource: 'test',
        source: 'role',
      },
    ],
  };

  const repository = {
    getScannableIdentities: jest.fn().mockResolvedValue([identity]),
  } as unknown as RiskRepository;
  const catalog = {
    getRules: jest.fn().mockReturnValue(rules),
  } as unknown as RuleCatalogService;
  const service = new RiskService(repository, catalog, new RiskEngineService());

  it('previews a score reduction without persisting changes', async () => {
    const result = await service.simulate('test-user', ['resource:approve']);

    expect(result.currentScore).toBe(35);
    expect(result.projectedScore).toBe(0);
    expect(result.resolvedFindings).toEqual(['Create and approve']);
    expect(repository.getScannableIdentities).toHaveBeenCalledTimes(1);
  });
});
