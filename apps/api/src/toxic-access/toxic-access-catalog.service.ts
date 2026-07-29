import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { ToxicCombinationRule } from './domain/toxic-access.types';

const requirementSchema = z.object({
  id: z.string().min(2),
  platform: z.string().min(2).optional(),
  anyPermissions: z.array(z.string().min(2)).min(1),
  resourcePattern: z.string().min(1).optional(),
});

const toxicCombinationRuleSchema = z.object({
  id: z.string().min(5),
  title: z.string().min(5),
  description: z.string().min(10),
  category: z.enum([
    'SEGREGATION_OF_DUTIES',
    'CROSS_PLATFORM_CONTROL',
    'SUPPLY_CHAIN_PIVOT',
    'DATA_CONTROL_CONFLICT',
  ]),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  businessImpact: z.string().min(10),
  remediation: z.string().min(10),
  requirements: z.array(requirementSchema).min(2),
  identityTypes: z.array(z.enum(['HUMAN', 'SERVICE_ACCOUNT', 'WORKLOAD'])).optional(),
  minimumPlatforms: z.number().int().min(2).optional(),
  mappings: z.object({
    mitre: z.array(z.string()),
    nist: z.array(z.string()).min(1),
  }),
});

@Injectable()
export class ToxicAccessCatalogService {
  private readonly rules: ToxicCombinationRule[];

  constructor() {
    try {
      const file = join(__dirname, 'rules', 'toxic-combinations.json');
      const parsed: unknown = JSON.parse(readFileSync(file, 'utf8'));
      this.rules = z.array(toxicCombinationRuleSchema).parse(parsed);
    } catch (error) {
      throw new InternalServerErrorException(
        `Toxic-access catalogue could not be loaded: ${
          error instanceof Error ? error.message : 'unknown error'
        }`,
      );
    }
  }

  getRules(): readonly ToxicCombinationRule[] {
    return this.rules;
  }
}
