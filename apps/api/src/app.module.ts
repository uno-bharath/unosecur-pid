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
import { ToxicAccessModule } from './toxic-access/toxic-access.module';

const environmentBoolean = z.preprocess(
  (value) => (typeof value === 'string' ? value.toLowerCase() === 'true' : value),
  z.boolean(),
);

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
  CLICKHOUSE_ENABLED: environmentBoolean.default(false),
  CLICKHOUSE_URL: z.string().url().default('http://127.0.0.1:8123'),
  CLICKHOUSE_USERNAME: z.string().default('pid_readonly'),
  CLICKHOUSE_PASSWORD: z.string().default(''),
  CLICKHOUSE_DATABASE: z
    .string()
    .regex(/^[A-Za-z0-9_]+$/)
    .default('unosecur_organization_replace_tenant_uno_id'),
  CLICKHOUSE_REQUEST_TIMEOUT_MS: z.coerce.number().int().positive().default(10000),
  CLICKHOUSE_REFRESH_INTERVAL_SECONDS: z.coerce.number().int().positive().default(15),
  KUBERNETES_ENABLED: environmentBoolean.default(false),
  KUBERNETES_CONTEXT_DISCOVERY: environmentBoolean.default(true),
  KUBERNETES_KUBECONFIG: z.string().default(''),
  KUBERNETES_CONTEXTS: z.string().default(''),
  KUBERNETES_INCLUDE_NAMESPACES: z.string().default(''),
  KUBERNETES_ALLOW_PRODUCTION: environmentBoolean.default(false),
  KUBERNETES_RESOURCE_LIMIT: z.coerce.number().int().positive().default(5000),
});

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['../../.env', '.env'],
      validate: (config) => environmentSchema.parse(config),
    }),
    ToxicAccessModule,
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
