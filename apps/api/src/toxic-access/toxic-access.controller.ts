import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { SimulateToxicAccessDto } from './dto/simulate-toxic-access.dto';
import { ToxicAccessEvaluation, ToxicAccessSimulation } from './domain/toxic-access.types';
import { ToxicAccessService } from './toxic-access.service';

@ApiTags('toxic-access')
@Controller('toxic-access')
export class ToxicAccessController {
  constructor(private readonly toxicAccessService: ToxicAccessService) {}

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
