import { Type } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  Max,
  MaxLength,
  Min,
  MinLength,
  ValidateNested,
} from 'class-validator';
import {
  AccessIdentityType,
  ConflictCategory,
  ConflictSeverity,
} from '../domain/toxic-access.types';

export class CustomRuleRequirementDto {
  @IsString()
  @MinLength(2)
  @MaxLength(80)
  id!: string;

  @IsOptional()
  @IsString()
  @MinLength(2)
  @MaxLength(80)
  platform?: string;

  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(20)
  @IsString({ each: true })
  anyPermissions!: string[];

  @IsOptional()
  @IsString()
  @MaxLength(240)
  resourcePattern?: string;
}

export class CreateCustomToxicRuleDto {
  @IsString()
  @MinLength(5)
  @MaxLength(120)
  title!: string;

  @IsString()
  @MinLength(10)
  @MaxLength(600)
  description!: string;

  @IsEnum([
    'SEGREGATION_OF_DUTIES',
    'CROSS_PLATFORM_CONTROL',
    'SUPPLY_CHAIN_PIVOT',
    'DATA_CONTROL_CONFLICT',
  ] satisfies ConflictCategory[])
  category!: ConflictCategory;

  @IsEnum(['critical', 'high', 'medium', 'low'] satisfies ConflictSeverity[])
  severity!: ConflictSeverity;

  @IsString()
  @MinLength(10)
  @MaxLength(600)
  businessImpact!: string;

  @IsString()
  @MinLength(10)
  @MaxLength(600)
  remediation!: string;

  @IsArray()
  @ArrayMinSize(2)
  @ArrayMaxSize(12)
  @ValidateNested({ each: true })
  @Type(() => CustomRuleRequirementDto)
  requirements!: CustomRuleRequirementDto[];

  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(3)
  @IsEnum(['HUMAN', 'SERVICE_ACCOUNT', 'WORKLOAD'] satisfies AccessIdentityType[], {
    each: true,
  })
  identityTypes!: AccessIdentityType[];

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(2)
  @Max(20)
  minimumPlatforms?: number;

  @IsArray()
  @ArrayMaxSize(20)
  @IsString({ each: true })
  mitreMappings!: string[];

  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(20)
  @IsString({ each: true })
  nistMappings!: string[];
}
