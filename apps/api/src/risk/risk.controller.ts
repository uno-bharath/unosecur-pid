import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { SimulateRiskDto } from './dto/simulate-risk.dto';
import { RiskService } from './risk.service';
import { RiskSimulation, RiskSummary, ToxicIdentity } from './risk.types';

@ApiTags('risk')
@Controller('risk')
export class RiskController {
  constructor(private readonly riskService: RiskService) {}

  @Get('summary')
  @ApiOperation({ summary: 'Get enterprise risk posture' })
  getSummary(): Promise<RiskSummary> {
    return this.riskService.getSummary();
  }

  @Get('identities')
  @ApiOperation({ summary: 'List toxic identities ranked by risk' })
  getIdentities(): Promise<ToxicIdentity[]> {
    return this.riskService.getIdentities();
  }

  @Get('identities/:id')
  @ApiOperation({ summary: 'Get explainable identity risk evidence' })
  getIdentity(@Param('id') id: string): Promise<ToxicIdentity> {
    return this.riskService.getIdentity(id);
  }

  @Post('scan')
  @ApiOperation({ summary: 'Evaluate all stored identities against the rule catalogue' })
  scan(): Promise<{ identitiesEvaluated: number; findingsCreated: number }> {
    return this.riskService.scan();
  }

  @Post('identities/:id/simulate')
  @ApiOperation({ summary: 'Preview risk reduction before permissions are removed' })
  simulate(@Param('id') id: string, @Body() input: SimulateRiskDto): Promise<RiskSimulation> {
    return this.riskService.simulate(id, input.removePermissions);
  }
}
