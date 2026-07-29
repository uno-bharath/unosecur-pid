import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { RiskRuleDefinition } from './risk.types';

const ruleSchema = z.object({
  id: z.string().min(3),
  title: z.string().min(3),
  platform: z.string().min(2),
  category: z.string().min(2),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  description: z.string().min(10),
  businessImpact: z.string().min(10),
  remediation: z.string().min(10),
  mitreMappings: z.array(z.string()).min(1),
  nistMappings: z.array(z.string()).min(1),
  riskWeight: z.number().int().min(1).max(100),
  confidence: z.number().min(0).max(100),
  matching: z.object({
    allPermissions: z.array(z.string()).optional(),
    anyPermissions: z.array(z.string()).optional(),
    minPlatforms: z.number().int().min(2).optional(),
    identityTypes: z.array(z.enum(['HUMAN', 'SERVICE_ACCOUNT', 'WORKLOAD'])).optional(),
    dormantDays: z.number().int().positive().optional(),
  }),
});

@Injectable()
export class RuleCatalogService {
  private readonly rules: RiskRuleDefinition[];

  constructor() {
    const path = join(__dirname, 'rules', 'catalog.json');
    try {
      const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
      this.rules = z.array(ruleSchema).parse(parsed);
    } catch (error) {
      throw new InternalServerErrorException(
        `Risk rule catalogue could not be loaded: ${error instanceof Error ? error.message : 'unknown error'}`,
      );
    }
  }

  getRules(): readonly RiskRuleDefinition[] {
    return this.rules;
  }
}
