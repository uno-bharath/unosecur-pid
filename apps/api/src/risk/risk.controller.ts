import { Controller, Get, Param } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { RiskService, RiskSummary, ToxicIdentity } from './risk.service';

@ApiTags('risk')
@Controller('risk')
export class RiskController {
  constructor(private readonly riskService: RiskService) {}

  @Get('summary')
  @ApiOperation({ summary: 'Get enterprise risk posture' })
  getSummary(): RiskSummary {
    return this.riskService.getSummary();
  }

  @Get('identities')
  @ApiOperation({ summary: 'List toxic identities ranked by risk' })
  getIdentities(): ToxicIdentity[] {
    return this.riskService.getIdentities();
  }

  @Get('identities/:id')
  @ApiOperation({ summary: 'Get explainable identity risk evidence' })
  getIdentity(@Param('id') id: string): ToxicIdentity {
    return this.riskService.getIdentity(id);
  }
}
