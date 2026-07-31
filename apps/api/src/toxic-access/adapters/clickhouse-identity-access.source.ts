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
  correlation_uno_id: string | null;
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
        correlation_uno_id,
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

    const snapshots = rows.map((row) => ({
      correlationId: row.correlation_uno_id,
      snapshot: this.toSnapshot(row),
    }));
    const merged = new Map<string, IdentityAccessSnapshot>();
    for (const { correlationId, snapshot } of snapshots) {
      const key = correlationId || snapshot.identityId;
      const current = merged.get(key);
      if (!current) {
        merged.set(key, { ...snapshot, identityId: key });
        continue;
      }
      current.grants.push(...snapshot.grants);
      if (current.provider !== snapshot.provider) current.provider = 'MULTI_PLATFORM';
    }
    return [...merged.values()];
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
    const provider = this.canonicalProvider(
      row.source || row.provider_entity_type.split(' - ')[0] || 'UNKNOWN',
    );
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
          .flatMap((value) => this.normalizePermissions(provider, value))
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

  private normalizePermissions(provider: string, value: string): string[] {
    const permission = value.trim();
    if (!permission || this.isOpaqueIdentifier(permission)) return [];
    if (provider === 'AWS') {
      const policyName = permission.includes('/') ? permission.split('/').pop() : permission;
      if (policyName === 'AdministratorAccess' || permission === '*' || permission === '*:*') {
        return [
          'aws:AdministratorAccess',
          'aws:*',
          'iam:PassRole',
          'iam:CreateAccessKey',
          'iam:CreatePolicyVersion',
          'sts:AssumeRole',
          'cloudtrail:StopLogging',
          'cloudtrail:DeleteTrail',
          's3:GetObject',
          's3:PutObject',
          's3:DeleteObject',
          'kms:CreateKey',
          'kms:Encrypt',
          'kms:Decrypt',
          'kms:ScheduleKeyDeletion',
        ];
      }
      const serviceWildcard = permission.match(/^([a-z0-9-]+):\*$/i);
      if (serviceWildcard) return [permission, ...this.expandAwsService(serviceWildcard[1])];
    }
    return [permission];
  }

  private expandAwsService(service: string): string[] {
    const expansions: Record<string, string[]> = {
      iam: ['iam:PassRole', 'iam:CreateAccessKey', 'iam:CreatePolicyVersion'],
      sts: ['sts:AssumeRole'],
      cloudtrail: ['cloudtrail:StopLogging', 'cloudtrail:DeleteTrail'],
      s3: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
      kms: ['kms:CreateKey', 'kms:Encrypt', 'kms:Decrypt', 'kms:ScheduleKeyDeletion'],
    };
    return expansions[service.toLowerCase()] ?? [];
  }

  private isOpaqueIdentifier(value: string): boolean {
    return /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(value) || /^[0-9a-f]{32,}$/i.test(value);
  }

  private canonicalProvider(provider: string): string {
    const normalized = provider.trim().toUpperCase();
    const names: Record<string, string> = {
      AWS: 'AWS',
      GCP: 'GCP',
      AZURE: 'Azure',
      ENTRA: 'Entra ID',
      GITHUB: 'GitHub',
      'GITHUB-EMU': 'GitHub',
      KUBERNETES: 'Kubernetes',
      'HASHI-CORP': 'Vault',
    };
    return names[normalized] ?? provider.trim();
  }
}
