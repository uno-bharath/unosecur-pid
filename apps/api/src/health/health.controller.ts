import { Controller, Get } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { HealthService, PlatformHealth } from './health.service';

@ApiTags('platform')
@Controller('health')
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Get()
  @ApiOperation({ summary: 'Check API and dependency readiness' })
  getHealth(): Promise<PlatformHealth> {
    return this.healthService.check();
  }
}
