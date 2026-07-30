import { ToxicAccessCatalogService } from './toxic-access-catalog.service';

describe('ToxicAccessCatalogService', () => {
  const rules = new ToxicAccessCatalogService().getRules();

  it('provides more than the required five deterministic toxic-combination rules', () => {
    expect(rules.length).toBeGreaterThanOrEqual(5);
  });

  it('covers the required abuse families with evidence requirements and remediation', () => {
    const requiredRuleIds = [
      'TAI-SOD-FIN-001',
      'TAI-XPLAT-CICD-001',
      'PID-AWS-AUDIT-001',
      'PID-AWS-DATA-001',
      'PID-AWS-KMS-001',
    ];

    for (const ruleId of requiredRuleIds) {
      const rule = rules.find(({ id }) => id === ruleId);
      expect(rule).toBeDefined();
      expect(rule?.requirements.length).toBeGreaterThanOrEqual(2);
      expect(rule?.businessImpact.length).toBeGreaterThan(20);
      expect(rule?.remediation.length).toBeGreaterThan(20);
    }
  });
});
