import { NotFoundException } from '@nestjs/common';
import { RiskService } from './risk.service';

describe('RiskService', () => {
  const service = new RiskService();

  it('ranks toxic identities by descending risk', () => {
    const scores = service.getIdentities().map((identity) => identity.riskScore);
    expect(scores).toEqual([...scores].sort((left, right) => right - left));
  });

  it('returns explainable evidence for the leading identity', () => {
    const identity = service.getIdentity('john-smith');
    expect(identity.factors.length).toBeGreaterThan(1);
    expect(identity.attackPath.at(-1)).toBe('Customer Database');
  });

  it('rejects an unknown identity', () => {
    expect(() => service.getIdentity('missing')).toThrow(NotFoundException);
  });
});
