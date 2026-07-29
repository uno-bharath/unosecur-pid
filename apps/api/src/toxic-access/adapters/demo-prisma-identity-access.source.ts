import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service';
import { IdentityAccessSnapshot } from '../domain/toxic-access.types';
import { IdentityAccessSource } from '../ports/identity-access-source';

/**
 * Hackathon-only adapter. Production integrations should implement the same port
 * using Uno Entities and effective-entitlement APIs.
 */
@Injectable()
export class DemoPrismaIdentityAccessSource extends IdentityAccessSource {
  readonly sourceName = 'demo-prisma';

  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async getIdentity(identityId: string): Promise<IdentityAccessSnapshot | null> {
    const identity = await this.prisma.identity.findUnique({
      where: { id: identityId },
      include: { grants: true },
    });
    return identity ? this.toSnapshot(identity) : null;
  }

  async listIdentities(): Promise<IdentityAccessSnapshot[]> {
    const identities = await this.prisma.identity.findMany({
      include: { grants: true },
      orderBy: { displayName: 'asc' },
    });
    return identities.map((identity) => this.toSnapshot(identity));
  }

  private toSnapshot(
    identity: Awaited<ReturnType<DemoPrismaIdentityAccessSource['findIdentityShape']>>,
  ): IdentityAccessSnapshot {
    return {
      identityId: identity.id,
      displayName: identity.displayName,
      type: identity.type,
      provider: identity.provider,
      grants: identity.grants.map((grant) => ({
        id: grant.id,
        platform: grant.platform,
        permission: grant.permission,
        resource: grant.resource,
        assignment: {
          source: grant.source,
          path: [identity.displayName, grant.source, grant.permission, grant.resource],
        },
      })),
    };
  }

  /**
   * Type-only helper that keeps the Prisma payload definition in one place.
   * It is never called at runtime.
   */
  private findIdentityShape() {
    return this.prisma.identity.findFirstOrThrow({ include: { grants: true } });
  }
}
