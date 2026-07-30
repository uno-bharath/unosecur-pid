import { Body, Controller, Delete, Get, HttpCode, Param, Post } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import {
  CustomRulePreview,
  CustomRuleRecord,
  CustomToxicRuleService,
} from './custom-toxic-rule.service';
import { CreateCustomToxicRuleDto } from './dto/create-custom-toxic-rule.dto';
import { SimulateToxicAccessDto } from './dto/simulate-toxic-access.dto';
import { ToxicAccessEvaluation, ToxicAccessSimulation } from './domain/toxic-access.types';
import { ToxicAccessService } from './toxic-access.service';

@ApiTags('toxic-access')
@Controller('toxic-access')
export class ToxicAccessController {
  constructor(
    private readonly toxicAccessService: ToxicAccessService,
    private readonly customRules: CustomToxicRuleService,
  ) {}

  @Get('rules/custom')
  @ApiOperation({ summary: 'List customer-defined toxic-combination rules' })
  listCustomRules(): Promise<CustomRuleRecord[]> {
    return this.customRules.list();
  }

  @Post('rules/custom/preview')
  @HttpCode(200)
  @ApiOperation({ summary: 'Test a rule against current identity evidence without saving it' })
  previewCustomRule(@Body() input: CreateCustomToxicRuleDto): Promise<CustomRulePreview> {
    return this.customRules.preview(input);
  }

  @Post('rules/custom')
  @ApiOperation({ summary: 'Save a validated customer rule as a draft' })
  createCustomRule(@Body() input: CreateCustomToxicRuleDto): Promise<CustomRuleRecord> {
    return this.customRules.create(input);
  }

  @Post('rules/custom/:id/publish')
  @HttpCode(200)
  @ApiOperation({ summary: 'Publish a tested customer rule into continuous evaluation' })
  publishCustomRule(@Param('id') id: string): Promise<CustomRuleRecord> {
    return this.customRules.publish(id);
  }

  @Delete('rules/custom/:id')
  @HttpCode(204)
  @ApiOperation({ summary: 'Delete an unpublished customer rule draft' })
  async deleteCustomRule(@Param('id') id: string): Promise<void> {
    await this.customRules.remove(id);
  }

  @Get('identities')
  @ApiOperation({ summary: 'List identities with deterministic entitlement conflicts' })
  listConflictedIdentities(): Promise<ToxicAccessEvaluation[]> {
    return this.toxicAccessService.listConflictedIdentities();
  }

  @Get('identities/:id')
  @ApiOperation({ summary: 'Explain toxic entitlement combinations and inheritance evidence' })
  evaluateIdentity(@Param('id') id: string): Promise<ToxicAccessEvaluation> {
    return this.toxicAccessService.evaluateIdentity(id);
  }

  @Post('identities/:id/simulate')
  @ApiOperation({ summary: 'Preview conflicts resolved by a proposed permission removal' })
  simulate(
    @Param('id') id: string,
    @Body() input: SimulateToxicAccessDto,
  ): Promise<ToxicAccessSimulation> {
    return this.toxicAccessService.simulate(id, input.removePermissions);
  }
}
