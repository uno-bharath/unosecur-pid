import { IdentityAccessSnapshot, ToxicCombinationRule } from './domain/toxic-access.types';
import { IdentityAccessSource } from './ports/identity-access-source';
import { ToxicAccessCatalogService } from './toxic-access-catalog.service';
import { ToxicAccessEngineService } from './toxic-access-engine.service';
import { ToxicAccessService } from './toxic-access.service';

const identity: IdentityAccessSnapshot = {
  identityId: 'finance-user',
  displayName: 'Finance User',
  type: 'HUMAN',
  provider: 'Entra ID',
  grants: [
    {
      id: 'create-grant',
      platform: 'ERP',
      permission: 'vendor:create',
      resource: 'erp:vendors',
      assignment: {
        source: 'operator-role',
        path: ['Finance User', 'operator-role', 'vendor:create'],
      },
    },
    {
      id: 'approve-grant',
      platform: 'ERP',
      permission: 'payment:approve',
      resource: 'erp:payments',
      assignment: {
        source: 'approver-role',
        path: ['Finance User', 'approver-role', 'payment:approve'],
      },
    },
    {
      id: 'read-grant',
      platform: 'ERP',
      permission: 'report:read',
      resource: 'erp:reports',
      assignment: { source: 'reader-role', path: ['Finance User', 'reader-role', 'report:read'] },
    },
  ],
};

const rule: ToxicCombinationRule = {
  id: 'TAI-TEST-SOD',
  title: 'Create and approve conflict',
  description: 'The identity controls both sides of a financial workflow.',
  category: 'SEGREGATION_OF_DUTIES',
  severity: 'critical',
  businessImpact: 'The identity can create and approve an unreviewed transaction.',
  remediation: 'Separate creation and approval into independently reviewed roles.',
  requirements: [
    { id: 'create', anyPermissions: ['vendor:create'] },
    { id: 'approve', anyPermissions: ['payment:approve'] },
  ],
  mappings: { mitre: [], nist: ['AC-5'] },
};

describe('ToxicAccessService', () => {
  const source = {
    sourceName: 'test-source',
    getIdentity: jest.fn().mockResolvedValue(identity),
    listIdentities: jest.fn().mockResolvedValue([identity]),
  } as unknown as IdentityAccessSource;
  const catalog = {
    getRules: jest.fn().mockReturnValue([rule]),
  } as unknown as ToxicAccessCatalogService;
  const service = new ToxicAccessService(source, catalog, new ToxicAccessEngineService());

  it('reports the source and deterministic conflict summary without a local risk score', async () => {
    const result = await service.evaluateIdentity(identity.identityId);

    expect(result.source).toBe('test-source');
    expect(result.summary).toMatchObject({ total: 1, critical: 1 });
    expect(result).not.toHaveProperty('riskScore');
  });

  it('simulates conflict resolution while preserving unrelated grants', async () => {
    const result = await service.simulate(identity.identityId, ['payment:approve']);

    expect(result.projectedConflictCount).toBe(0);
    expect(result.resolvedConflicts).toEqual(['Create and approve conflict']);
    expect(result.preservedGrantCount).toBe(2);
  });
});
