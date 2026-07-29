import { Body, Controller, Post } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { CopilotAnswer, CopilotService } from './copilot.service';
import { AskCopilotDto } from './dto/ask-copilot.dto';

@ApiTags('copilot')
@Controller('copilot')
export class CopilotController {
  constructor(private readonly copilot: CopilotService) {}

  @Post('ask')
  @ApiOperation({ summary: 'Ask the local, evidence-grounded identity security copilot' })
  ask(@Body() input: AskCopilotDto): Promise<CopilotAnswer> {
    return this.copilot.ask(input.question, input.identityId);
  }
}
