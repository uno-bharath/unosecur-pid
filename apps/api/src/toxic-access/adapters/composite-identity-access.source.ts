import { Injectable } from '@nestjs/common';
import { IdentityAccessSnapshot } from '../domain/toxic-access.types';
import { IdentityAccessSource } from '../ports/identity-access-source';

@Injectable()
export class CompositeIdentityAccessSource extends IdentityAccessSource {
  readonly sourceName = 'unosecur-clickhouse+kubernetes';

  constructor(private readonly sources: readonly IdentityAccessSource[]) {
    super();
  }

  async getIdentity(identityId: string): Promise<IdentityAccessSnapshot | null> {
    for (const source of this.sources) {
      const identity = await source.getIdentity(identityId);
      if (identity) return identity;
    }
    return null;
  }

  async listIdentities(): Promise<IdentityAccessSnapshot[]> {
    return (await Promise.all(this.sources.map((source) => source.listIdentities()))).flat();
  }
}
