import { PrismaService } from '../database/prisma.service';
import { CustomToxicRuleService } from './custom-toxic-rule.service';
import { CreateCustomToxicRuleDto } from './dto/create-custom-toxic-rule.dto';
import { IdentityAccessSource } from './ports/identity-access-source';
import { ToxicAccessEngineService } from './toxic-access-engine.service';

describe('CustomToxicRuleService', () => {
  const input: CreateCustomToxicRuleDto = {
    title: 'Audit shutdown and log deletion',
    description: 'Detects identities that can stop audit collection and delete retained logs.',
    category: 'SEGREGATION_OF_DUTIES',
    severity: 'critical',
    businessImpact: 'An attacker can suppress the evidence needed for investigation.',
    remediation: 'Separate audit administration from protected log-storage deletion.',
    requirements: [
      {
        id: 'stop-audit',
        platform: 'AWS',
        anyPermissions: ['cloudtrail:StopLogging'],
      },
      {
        id: 'delete-logs',
        platform: 'AWS',
        anyPermissions: ['s3:DeleteObject'],
      },
    ],
    identityTypes: ['HUMAN', 'SERVICE_ACCOUNT', 'WORKLOAD'],
    mitreMappings: ['T1562.008'],
    nistMappings: ['AC-5', 'AU-9'],
  };

  const source = {
    sourceName: 'test',
    listIdentities: jest.fn().mockResolvedValue([
      {
        identityId: 'legacy-admin',
        displayName: 'legacy-admin',
        type: 'SERVICE_ACCOUNT',
        provider: 'AWS',
        grants: [
          {
            id: 'grant-1',
            platform: 'AWS',
            permission: 'cloudtrail:StopLogging',
            resource: 'aws:cloudtrail:organization',
            assignment: { source: 'role', path: ['legacy-admin', 'role', 'permission'] },
          },
          {
            id: 'grant-2',
            platform: 'AWS',
            permission: 's3:DeleteObject',
            resource: 'aws:s3:audit-logs',
            assignment: { source: 'role', path: ['legacy-admin', 'role', 'permission'] },
          },
        ],
      },
    ]),
  } as unknown as IdentityAccessSource;
  const prisma = {
    customToxicRule: {
      findMany: jest.fn().mockResolvedValue([]),
    },
  } as unknown as PrismaService;
  const service = new CustomToxicRuleService(prisma, new ToxicAccessEngineService(), source);

  it('previews a customer rule against effective-access evidence without saving it', async () => {
    const result = await service.preview(input);

    expect(result.affectedIdentityCount).toBe(1);
    expect(result.affectedIdentities[0]).toEqual(
      expect.objectContaining({
        identityId: 'legacy-admin',
        matchedPermissions: ['cloudtrail:StopLogging', 's3:DeleteObject'],
      }),
    );
    expect(prisma.customToxicRule.findMany).not.toHaveBeenCalled();
  });
});
