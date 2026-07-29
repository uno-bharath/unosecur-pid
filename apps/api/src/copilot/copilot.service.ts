import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ToxicAccessEvaluation } from '../toxic-access/domain/toxic-access.types';
import { ToxicAccessService } from '../toxic-access/toxic-access.service';

interface OllamaResponse {
  message?: { content?: string };
}

export interface CopilotAnswer {
  answer: string;
  identityId: string;
  model: string;
  source: 'ollama' | 'deterministic-fallback';
  evidence: {
    conflicts: number;
    criticalConflicts: number;
    platforms: string[];
  };
}

@Injectable()
export class CopilotService {
  constructor(
    private readonly config: ConfigService,
    private readonly toxicAccessService: ToxicAccessService,
  ) {}

  async ask(question: string, identityId?: string): Promise<CopilotAnswer> {
    const identity = identityId
      ? await this.toxicAccessService.evaluateIdentity(identityId)
      : (await this.toxicAccessService.listConflictedIdentities())[0];
    if (!identity) {
      throw new Error('No identity with a toxic access conflict is available');
    }

    const model = this.config.get<string>('OLLAMA_MODEL', 'llama3:8b-instruct-q4_K_M');
    const baseUrl = this.config.get<string>('OLLAMA_BASE_URL', 'http://127.0.0.1:11434');
    const evidence = {
      conflicts: identity.summary.total,
      criticalConflicts: identity.summary.critical,
      platforms: identity.summary.affectedPlatforms,
    };

    try {
      const response = await fetch(`${baseUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(60_000),
        body: JSON.stringify({
          model,
          stream: false,
          keep_alive: '30m',
          messages: [
            {
              role: 'system',
              content:
                'You are UnoSecur Copilot. Use only the supplied evidence. Be concise, explain the attack path and business impact, and recommend specific least-privilege remediation. Never invent permissions or affected assets.',
            },
            {
              role: 'user',
              content: `${question}\n\nIdentity evidence:\n${JSON.stringify(identity)}`,
            },
          ],
          options: { num_predict: 400, temperature: 0.2 },
        }),
      });
      if (!response.ok) {
        throw new Error(`Ollama returned ${response.status}`);
      }
      const payload = (await response.json()) as OllamaResponse;
      const answer = payload.message?.content?.trim();
      if (!answer) throw new Error('Ollama returned an empty response');

      return { answer, identityId: identity.identityId, model, source: 'ollama', evidence };
    } catch {
      return {
        answer: this.fallback(identity),
        identityId: identity.identityId,
        model,
        source: 'deterministic-fallback',
        evidence,
      };
    }
  }

  private fallback(identity: ToxicAccessEvaluation): string {
    const topConflict = identity.conflicts[0];
    return `${identity.displayName} has ${identity.summary.total} deterministic entitlement conflict${
      identity.summary.total === 1 ? '' : 's'
    } across ${identity.summary.affectedPlatforms.join(', ')}. The leading conflict is ${
      topConflict?.title ?? 'excessive combined access'
    }. ${
      topConflict?.businessImpact ?? 'A compromise could cross multiple control planes.'
    } Recommended first action: ${
      topConflict?.remediation ?? 'remove one side of the conflict and require independent approval.'
    }`;
  }
}
