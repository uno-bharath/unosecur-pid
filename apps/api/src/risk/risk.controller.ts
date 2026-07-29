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
  @ApiOperation({
    summary: 'Get demo risk posture (compatibility endpoint)',
    description:
      'Hackathon compatibility endpoint. Production risk scores are owned by Uno Scoring.',
    deprecated: true,
  })
  getSummary(): Promise<RiskSummary> {
    return this.riskService.getSummary();
  }

  @Get('identities')
  @ApiOperation({
    summary: 'List demo identities ranked by local score',
    description:
      'Hackathon compatibility endpoint. Use /toxic-access for entitlement conflicts.',
    deprecated: true,
  })
  getIdentities(): Promise<ToxicIdentity[]> {
    return this.riskService.getIdentities();
  }

  @Get('identities/:id')
  @ApiOperation({
    summary: 'Get demo identity risk evidence',
    description:
      'Hackathon compatibility endpoint. Production findings are owned by Uno Detect.',
    deprecated: true,
  })
  getIdentity(@Param('id') id: string): Promise<ToxicIdentity> {
    return this.riskService.getIdentity(id);
  }

  @Post('scan')
  @ApiOperation({
    summary: 'Run demo-only local risk evaluation',
    description:
      'Temporary MVP behavior; this does not replace Uno Scoring or Uno Detect.',
    deprecated: true,
  })
  scan(): Promise<{ identitiesEvaluated: number; findingsCreated: number }> {
    return this.riskService.scan();
  }

  @Post('identities/:id/simulate')
  @ApiOperation({
    summary: 'Preview demo score reduction',
    description:
      'Compatibility endpoint. Use /toxic-access/identities/:id/simulate for conflict resolution.',
    deprecated: true,
  })
  simulate(@Param('id') id: string, @Body() input: SimulateRiskDto): Promise<RiskSimulation> {
    return this.riskService.simulate(id, input.removePermissions);
  }
}
