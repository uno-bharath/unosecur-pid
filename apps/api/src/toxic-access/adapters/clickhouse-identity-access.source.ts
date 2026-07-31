import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  AccessIdentityType,
  EffectiveGrant,
  IdentityAccessSnapshot,
} from '../domain/toxic-access.types';
import { IdentityAccessSource } from '../ports/identity-access-source';

interface UnoEntityRow {
  _id: string;
  name: string;
  uno_type: string | null;
  provider_entity_type: string;
  uno_sub_type: string[];
  source: string | null;
  details: string | null;
  attributes: string | null;
}

const PERMISSION_KEYS = new Set([
  'action',
  'actions',
  'permission',
  'permissions',
  'policyarn',
  'policyname',
  'entitlement',
  'entitlements',
  'privilege',
  'privileges',
  'role',
  'roles',
  'scope',
  'scopes',
]);

const RESOURCE_KEYS = [
  'resource',
  'resourceId',
  'resource_id',
  'scope',
  'arn',
  'project',
  'subscription',
];

@Injectable()
export class ClickHouseIdentityAccessSource extends IdentityAccessSource {
  readonly sourceName = 'unosecur-clickhouse';

  constructor(private readonly config: ConfigService) {
    super();
  }

  async getIdentity(identityId: string): Promise<IdentityAccessSnapshot | null> {
    return (await this.listIdentities()).find(({ identityId: id }) => id === identityId) ?? null;
  }

  async listIdentities(): Promise<IdentityAccessSnapshot[]> {
    const database = this.config.getOrThrow<string>('CLICKHOUSE_DATABASE');
    const rows = await this.query<UnoEntityRow>(`
      SELECT
        _id,
        name,
        uno_type,
        provider_entity_type,
        uno_sub_type,
        source,
        details,
        attributes
      FROM \`${database}\`.uno_entities FINAL
      WHERE uno_type IN ('provider_identity_human', 'provider_identity_nhi')
         OR positionCaseInsensitive(provider_entity_type, 'USER') > 0
         OR positionCaseInsensitive(provider_entity_type, 'NHI') > 0
      ORDER BY updated_at DESC
      LIMIT 10000
      FORMAT JSONEachRow
    `);

    return rows.map((row) => this.toSnapshot(row));
  }

  private async query<T>(query: string): Promise<T[]> {
    const baseUrl = this.config.getOrThrow<string>('CLICKHOUSE_URL').replace(/\/$/, '');
    const username = this.config.getOrThrow<string>('CLICKHOUSE_USERNAME');
    const password = this.config.get<string>('CLICKHOUSE_PASSWORD') ?? '';
    const timeout = this.config.get<number>('CLICKHOUSE_REQUEST_TIMEOUT_MS') ?? 10000;

    try {
      const response = await fetch(baseUrl, {
        method: 'POST',
        headers: {
          Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`,
          'Content-Type': 'text/plain; charset=utf-8',
        },
        body: query,
        signal: AbortSignal.timeout(timeout),
      });
      if (!response.ok) {
        throw new Error(`ClickHouse returned HTTP ${response.status}`);
      }
      const body = await response.text();
      return body
        .split('\n')
        .filter(Boolean)
        .map((line) => JSON.parse(line) as T);
    } catch (error) {
      const reason = error instanceof Error ? error.message : 'unknown connection error';
      throw new ServiceUnavailableException(`UnoSecur evidence source is unavailable: ${reason}`);
    }
  }

  private toSnapshot(row: UnoEntityRow): IdentityAccessSnapshot {
    const provider = (
      row.source ||
      row.provider_entity_type.split(' - ')[0] ||
      'UNKNOWN'
    ).toUpperCase();
    const details = this.parseJson(row.details);
    const attributes = this.parseJson(row.attributes);
    const resource =
      this.findResource(details) ?? this.findResource(attributes) ?? `${provider}:organization`;
    const permissionValues = [
      ...this.findPermissions(details),
      ...this.findPermissions(attributes),
    ];
    const permissions = [
      ...new Set(
        permissionValues
          .map((value) => this.normalizePermission(provider, value))
          .filter((value) => value.length > 0),
      ),
    ];
    const grants: EffectiveGrant[] = permissions.map((permission, index) => ({
      id: `${row._id}:grant:${index}`,
      platform: provider,
      permission,
      resource,
      assignment: {
        source: row.uno_sub_type[0] ?? row.provider_entity_type,
        path: [row.name, row.uno_sub_type[0] ?? row.provider_entity_type, permission, resource],
      },
    }));

    return {
      identityId: row._id,
      displayName: row.name || row._id,
      type: this.identityType(row),
      provider,
      grants,
    };
  }

  private identityType(row: UnoEntityRow): AccessIdentityType {
    if (row.uno_type === 'provider_identity_human' || /USER/i.test(row.provider_entity_type)) {
      return 'HUMAN';
    }
    const subtype = row.uno_sub_type.join(' ').toLowerCase();
    return /workload|pod|function|application|agent/.test(subtype) ? 'WORKLOAD' : 'SERVICE_ACCOUNT';
  }

  private parseJson(value: string | null): unknown {
    if (!value) return null;
    try {
      return JSON.parse(value) as unknown;
    } catch {
      return null;
    }
  }

  private findPermissions(value: unknown, parentKey = '', depth = 0): string[] {
    if (depth > 8 || value === null || value === undefined) return [];
    if (typeof value === 'string') {
      return PERMISSION_KEYS.has(parentKey) && value.length <= 512 ? [value] : [];
    }
    if (Array.isArray(value)) {
      return value.flatMap((item) => this.findPermissions(item, parentKey, depth + 1));
    }
    if (typeof value !== 'object') return [];
    return Object.entries(value as Record<string, unknown>).flatMap(([key, item]) =>
      this.findPermissions(item, key.toLowerCase(), depth + 1),
    );
  }

  private findResource(value: unknown, depth = 0): string | null {
    if (depth > 6 || !value || typeof value !== 'object') return null;
    const record = value as Record<string, unknown>;
    for (const key of RESOURCE_KEYS) {
      const candidate = record[key];
      if (typeof candidate === 'string' && candidate.length > 0) return candidate;
    }
    for (const candidate of Object.values(record)) {
      if (Array.isArray(candidate)) continue;
      const nested = this.findResource(candidate, depth + 1);
      if (nested) return nested;
    }
    return null;
  }

  private normalizePermission(provider: string, value: string): string {
    const permission = value.trim();
    if (provider === 'AWS') {
      const policyName = permission.includes('/') ? permission.split('/').pop() : permission;
      if (policyName === 'AdministratorAccess') return 'aws:AdministratorAccess';
    }
    return permission;
  }
}
