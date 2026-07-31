import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../database/prisma.service';
import { DemoPrismaIdentityAccessSource } from './adapters/demo-prisma-identity-access.source';
import { ClickHouseIdentityAccessSource } from './adapters/clickhouse-identity-access.source';
import { CompositeIdentityAccessSource } from './adapters/composite-identity-access.source';
import { KubernetesIdentityAccessSource } from './adapters/kubernetes-identity-access.source';
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
    KubernetesIdentityAccessSource,
    {
      provide: IDENTITY_ACCESS_SOURCE,
      inject: [DemoPrismaIdentityAccessSource, ClickHouseIdentityAccessSource, KubernetesIdentityAccessSource, ConfigService],
      useFactory: (
        demoSource: DemoPrismaIdentityAccessSource,
        clickHouseSource: ClickHouseIdentityAccessSource,
        kubernetesSource: KubernetesIdentityAccessSource,
        config: ConfigService,
      ) => {
        const sources = [];
        if (config.get<boolean>('CLICKHOUSE_ENABLED')) sources.push(clickHouseSource);
        if (config.get<boolean>('KUBERNETES_ENABLED')) sources.push(kubernetesSource);
        if (sources.length === 0) return demoSource;
        if (sources.length === 1) return sources[0];
        return new CompositeIdentityAccessSource(sources);
      },
    },
  ],
  exports: [ToxicAccessService],
})
export class ToxicAccessModule {}
