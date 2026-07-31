import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../database/prisma.service';
import { DemoPrismaIdentityAccessSource } from './adapters/demo-prisma-identity-access.source';
import { ClickHouseIdentityAccessSource } from './adapters/clickhouse-identity-access.source';
import { CustomToxicRuleService } from './custom-toxic-rule.service';
import { IDENTITY_ACCESS_SOURCE } from './ports/identity-access-source';
import { ToxicAccessCatalogService } from './toxic-access-catalog.service';
import { ToxicAccessController } from './toxic-access.controller';
import { ToxicAccessEngineService } from './toxic-access-engine.service';
import { ToxicAccessService } from './toxic-access.service';

@Module({
  controllers: [ToxicAccessController],
  providers: [
    PrismaService,
    ToxicAccessCatalogService,
    ToxicAccessEngineService,
    CustomToxicRuleService,
    ToxicAccessService,
    DemoPrismaIdentityAccessSource,
    ClickHouseIdentityAccessSource,
    {
      provide: IDENTITY_ACCESS_SOURCE,
      inject: [DemoPrismaIdentityAccessSource, ClickHouseIdentityAccessSource, ConfigService],
      useFactory: (
        demoSource: DemoPrismaIdentityAccessSource,
        clickHouseSource: ClickHouseIdentityAccessSource,
        config: ConfigService,
      ) => (config.get<boolean>('CLICKHOUSE_ENABLED') ? clickHouseSource : demoSource),
    },
  ],
  exports: [ToxicAccessService],
})
export class ToxicAccessModule {}
