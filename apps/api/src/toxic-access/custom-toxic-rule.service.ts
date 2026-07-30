import { BadRequestException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { CustomToxicRule, Prisma, Severity } from '@prisma/client';
import { PrismaService } from '../database/prisma.service';
import { CreateCustomToxicRuleDto } from './dto/create-custom-toxic-rule.dto';
import { ConflictSeverity, ToxicCombinationRule } from './domain/toxic-access.types';
import { IDENTITY_ACCESS_SOURCE, IdentityAccessSource } from './ports/identity-access-source';
import { ToxicAccessEngineService } from './toxic-access-engine.service';

export interface CustomRuleRecord {
  id: string;
  rule: ToxicCombinationRule;
  status: 'DRAFT' | 'PUBLISHED';
  version: number;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  publishedAt: string | null;
}

export interface CustomRulePreview {
  affectedIdentities: Array<{
    identityId: string;
    displayName: string;
    identityType: string;
    matchedPermissions: string[];
  }>;
  affectedIdentityCount: number;
  matchedGrantCount: number;
}

@Injectable()
export class CustomToxicRuleService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly engine: ToxicAccessEngineService,
    @Inject(IDENTITY_ACCESS_SOURCE)
    private readonly accessSource: IdentityAccessSource,
  ) {}

  async list(): Promise<CustomRuleRecord[]> {
    const records = await this.prisma.customToxicRule.findMany({
      orderBy: [{ status: 'asc' }, { updatedAt: 'desc' }],
    });
    return records.map((record) => this.toRecord(record));
  }

  async create(input: CreateCustomToxicRuleDto): Promise<CustomRuleRecord> {
    const rule = this.toRule(input, this.createRuleId(input.title));
    const record = await this.prisma.customToxicRule.create({
      data: {
        ruleId: rule.id,
        title: rule.title,
        description: rule.description,
        category: rule.category,
        severity: this.toDatabaseSeverity(rule.severity),
        businessImpact: rule.businessImpact,
        remediation: rule.remediation,
        requirements: rule.requirements as unknown as Prisma.InputJsonValue,
        identityTypes: rule.identityTypes ?? [],
        minimumPlatforms: rule.minimumPlatforms,
        mappings: rule.mappings as unknown as Prisma.InputJsonValue,
      },
    });
    return this.toRecord(record);
  }

  async preview(input: CreateCustomToxicRuleDto): Promise<CustomRulePreview> {
    const rule = this.toRule(input, 'CUSTOM-PREVIEW');
    const identities = await this.accessSource.listIdentities();
    const affectedIdentities = identities.flatMap((identity) => {
      const conflicts = this.engine.evaluate(identity, [rule]);
      return conflicts.map((conflict) => ({
        identityId: identity.identityId,
        displayName: identity.displayName,
        identityType: identity.type,
        matchedPermissions: conflict.evidence.map(({ permission }) => permission),
      }));
    });
    return {
      affectedIdentities,
      affectedIdentityCount: affectedIdentities.length,
      matchedGrantCount: affectedIdentities.reduce(
        (total, identity) => total + identity.matchedPermissions.length,
        0,
      ),
    };
  }

  async publish(id: string): Promise<CustomRuleRecord> {
    await this.requireRule(id);
    const record = await this.prisma.customToxicRule.update({
      where: { id },
      data: { status: 'PUBLISHED', publishedAt: new Date() },
    });
    return this.toRecord(record);
  }

  async remove(id: string): Promise<void> {
    const rule = await this.requireRule(id);
    if (rule.status === 'PUBLISHED') {
      throw new BadRequestException(
        'Published rules must be retired through an approved governance workflow.',
      );
    }
    await this.prisma.customToxicRule.delete({ where: { id } });
  }

  async getPublishedRules(): Promise<ToxicCombinationRule[]> {
    const records = await this.prisma.customToxicRule.findMany({
      where: { status: 'PUBLISHED' },
      orderBy: { createdAt: 'asc' },
    });
    return records.map((record) => this.toRuleFromRecord(record));
  }

  private async requireRule(id: string): Promise<CustomToxicRule> {
    const record = await this.prisma.customToxicRule.findUnique({ where: { id } });
    if (!record) throw new NotFoundException(`Custom rule ${id} was not found`);
    return record;
  }

  private toRule(input: CreateCustomToxicRuleDto, id: string): ToxicCombinationRule {
    return {
      id,
      title: input.title.trim(),
      description: input.description.trim(),
      category: input.category,
      severity: input.severity,
      businessImpact: input.businessImpact.trim(),
      remediation: input.remediation.trim(),
      requirements: input.requirements.map((requirement, index) => ({
        id: requirement.id.trim() || `condition-${index + 1}`,
        platform: requirement.platform?.trim() || undefined,
        anyPermissions: requirement.anyPermissions.map((permission) => permission.trim()),
        resourcePattern: requirement.resourcePattern?.trim() || undefined,
      })),
      identityTypes: input.identityTypes,
      minimumPlatforms: input.minimumPlatforms,
      mappings: {
        mitre: input.mitreMappings.map((mapping) => mapping.trim()).filter(Boolean),
        nist: input.nistMappings.map((mapping) => mapping.trim()).filter(Boolean),
      },
    };
  }

  private toRecord(record: CustomToxicRule): CustomRuleRecord {
    return {
      id: record.id,
      rule: this.toRuleFromRecord(record),
      status: record.status as 'DRAFT' | 'PUBLISHED',
      version: record.version,
      createdBy: record.createdBy,
      createdAt: record.createdAt.toISOString(),
      updatedAt: record.updatedAt.toISOString(),
      publishedAt: record.publishedAt?.toISOString() ?? null,
    };
  }

  private toRuleFromRecord(record: CustomToxicRule): ToxicCombinationRule {
    return {
      id: record.ruleId,
      title: record.title,
      description: record.description,
      category: record.category as ToxicCombinationRule['category'],
      severity: record.severity.toLowerCase() as ConflictSeverity,
      businessImpact: record.businessImpact,
      remediation: record.remediation,
      requirements: record.requirements as unknown as ToxicCombinationRule['requirements'],
      identityTypes: record.identityTypes as ToxicCombinationRule['identityTypes'],
      minimumPlatforms: record.minimumPlatforms ?? undefined,
      mappings: record.mappings as unknown as ToxicCombinationRule['mappings'],
    };
  }

  private toDatabaseSeverity(severity: ConflictSeverity): Severity {
    return severity.toUpperCase() as Severity;
  }

  private createRuleId(title: string): string {
    const slug = title
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 32);
    return `CUSTOM-${slug}-${Date.now().toString(36).toUpperCase()}`;
  }
}
