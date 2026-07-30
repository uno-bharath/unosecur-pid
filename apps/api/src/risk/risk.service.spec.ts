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
    getToxicIdentities: jest.fn().mockResolvedValue(
      Array.from({ length: 7 }, (_, index) => ({
        id: `identity-${index + 1}`,
        name: `Identity ${index + 1}`,
        type: index < 3 ? ('Human' as const) : ('Service account' as const),
        department: 'Security',
        riskScore: 80 - index,
        confidence: 95,
        platforms: ['AWS'],
        blastRadius: { accounts: 1, clusters: 0, secrets: 1, databases: 0 },
        factors: [],
        attackPath: ['Identity', 'AWS'],
      })),
    ),
    getFindingCount: jest.fn().mockResolvedValue(9),
    getPostureTrend: jest.fn().mockResolvedValue([
      {
        date: '2026-07-01T00:00:00.000Z',
        toxicIdentities: 10,
        totalConflicts: 24,
        criticalConflicts: 16,
        newConflicts: 3,
        remediatedConflicts: 0,
        attackPaths: 12,
      },
      {
        date: '2026-07-30T00:00:00.000Z',
        toxicIdentities: 7,
        totalConflicts: 16,
        criticalConflicts: 13,
        newConflicts: 1,
        remediatedConflicts: 6,
        attackPaths: 9,
      },
    ]),
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

  it('summarizes historical posture and remediation impact', async () => {
    const result = await service.getExecutiveTrend(30);

    expect(result.periodDays).toBe(30);
    expect(result.summary.toxicIdentityChange).toBe(-3);
    expect(result.summary.toxicIdentityChangePercent).toBe(-30);
    expect(result.summary.conflictsRemediated).toBe(6);
    expect(result.summary.netConflictChange).toBe(-8);
  });

  it('returns every affected identity so the displayed queue matches its total', async () => {
    const result = await service.getSummary();

    expect(result.identitiesScanned).toBe(7);
    expect(result.topIdentities).toHaveLength(7);
  });
});
