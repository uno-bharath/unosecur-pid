import { Module } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import { DemoPrismaIdentityAccessSource } from './adapters/demo-prisma-identity-access.source';
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
    ToxicAccessService,
    {
      provide: IDENTITY_ACCESS_SOURCE,
      useClass: DemoPrismaIdentityAccessSource,
    },
  ],
  exports: [ToxicAccessService],
})
export class ToxicAccessModule {}
