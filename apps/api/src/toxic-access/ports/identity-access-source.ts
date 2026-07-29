import { IdentityAccessSnapshot } from '../domain/toxic-access.types';

export const IDENTITY_ACCESS_SOURCE = Symbol('IDENTITY_ACCESS_SOURCE');

export abstract class IdentityAccessSource {
  abstract readonly sourceName: string;
  abstract getIdentity(identityId: string): Promise<IdentityAccessSnapshot | null>;
  abstract listIdentities(): Promise<IdentityAccessSnapshot[]>;
}
