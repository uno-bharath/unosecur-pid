import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import neo4j from 'neo4j-driver';
import { PrismaClient } from '@prisma/client';

type DependencyState = 'up' | 'down';

export interface PlatformHealth {
  status: 'ok' | 'degraded';
  timestamp: string;
  dependencies: Record<'postgres' | 'redis' | 'neo4j' | 'ollama', DependencyState>;
}

@Injectable()
export class HealthService {
  constructor(private readonly config: ConfigService) {}

  async check(): Promise<PlatformHealth> {
    const checks = await Promise.all([
      this.checkPostgres(),
      this.checkRedis(),
      this.checkNeo4j(),
      this.checkOllama(),
    ]);
    const dependencies: PlatformHealth['dependencies'] = {
      postgres: checks[0],
      redis: checks[1],
      neo4j: checks[2],
      ollama: checks[3],
    };

    return {
      status: checks.every((state) => state === 'up') ? 'ok' : 'degraded',
      timestamp: new Date().toISOString(),
      dependencies,
    };
  }

  private async checkPostgres(): Promise<DependencyState> {
    const client = new PrismaClient();
    try {
      await client.$queryRaw`SELECT 1`;
      return 'up';
    } catch {
      return 'down';
    } finally {
      await client.$disconnect();
    }
  }

  private async checkRedis(): Promise<DependencyState> {
    const client = new Redis(this.config.getOrThrow<string>('REDIS_URL'), {
      lazyConnect: true,
      connectTimeout: 750,
      maxRetriesPerRequest: 0,
    });
    client.on('error', () => undefined);
    try {
      await client.connect();
      return (await client.ping()) === 'PONG' ? 'up' : 'down';
    } catch {
      return 'down';
    } finally {
      client.disconnect();
    }
  }

  private async checkNeo4j(): Promise<DependencyState> {
    const driver = neo4j.driver(
      this.config.getOrThrow<string>('NEO4J_URI'),
      neo4j.auth.basic(
        this.config.getOrThrow<string>('NEO4J_USER'),
        this.config.getOrThrow<string>('NEO4J_PASSWORD'),
      ),
    );
    try {
      await driver.verifyConnectivity({ database: 'neo4j' });
      return 'up';
    } catch {
      return 'down';
    } finally {
      await driver.close();
    }
  }

  private async checkOllama(): Promise<DependencyState> {
    try {
      const response = await fetch(
        `${this.config.getOrThrow<string>('OLLAMA_BASE_URL')}/api/tags`,
        {
          signal: AbortSignal.timeout(1000),
        },
      );
      return response.ok ? 'up' : 'down';
    } catch {
      return 'down';
    }
  }
}
