import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { z } from 'zod';
import { CopilotController } from './copilot/copilot.controller';
import { CopilotService } from './copilot/copilot.service';
import { HealthController } from './health/health.controller';
import { HealthService } from './health/health.service';
import { PrismaService } from './database/prisma.service';
import { RiskEngineService } from './risk/risk-engine.service';
import { RiskRepository } from './risk/risk.repository';
import { RiskController } from './risk/risk.controller';
import { RiskService } from './risk/risk.service';
import { RuleCatalogService } from './risk/rule-catalog.service';

const environmentSchema = z.object({
  API_PORT: z.coerce.number().default(4000),
  DATABASE_URL: z
    .string()
    .default('postgresql://enterprise:enterprise_dev@localhost:5432/enterprise_ai'),
  REDIS_URL: z.string().default('redis://:redis_dev@localhost:6379'),
  NEO4J_URI: z.string().default('neo4j://localhost:7687'),
  NEO4J_USER: z.string().default('neo4j'),
  NEO4J_PASSWORD: z.string().default('neo4j_dev_password'),
  OLLAMA_BASE_URL: z.string().url().default('http://127.0.0.1:11434'),
  OLLAMA_MODEL: z.string().default('llama3:8b-instruct-q4_K_M'),
});

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validate: (config) => environmentSchema.parse(config),
    }),
  ],
  controllers: [HealthController, RiskController, CopilotController],
  providers: [
    PrismaService,
    HealthService,
    RiskRepository,
    RuleCatalogService,
    RiskEngineService,
    RiskService,
    CopilotService,
  ],
})
export class AppModule {}
