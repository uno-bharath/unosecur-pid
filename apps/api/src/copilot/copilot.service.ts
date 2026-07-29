import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { RiskService } from '../risk/risk.service';
import { ToxicIdentity } from '../risk/risk.types';

interface OllamaResponse {
  message?: { content?: string };
}

export interface CopilotAnswer {
  answer: string;
  identityId: string;
  model: string;
  source: 'ollama' | 'deterministic-fallback';
  evidence: {
    riskScore: number;
    confidence: number;
    matchedRules: number;
    platforms: string[];
  };
}

@Injectable()
export class CopilotService {
  constructor(
    private readonly config: ConfigService,
    private readonly riskService: RiskService,
  ) {}

  async ask(question: string, identityId?: string): Promise<CopilotAnswer> {
    const identity = identityId
      ? await this.riskService.getIdentity(identityId)
      : (await this.riskService.getIdentities())[0];

    const model = this.config.get<string>('OLLAMA_MODEL', 'llama3:8b-instruct-q4_K_M');
    const baseUrl = this.config.get<string>('OLLAMA_BASE_URL', 'http://127.0.0.1:11434');
    const evidence = {
      riskScore: identity.riskScore,
      confidence: identity.confidence,
      matchedRules: identity.factors.length,
      platforms: identity.platforms,
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

      return { answer, identityId: identity.id, model, source: 'ollama', evidence };
    } catch {
      return {
        answer: this.fallback(identity),
        identityId: identity.id,
        model,
        source: 'deterministic-fallback',
        evidence,
      };
    }
  }

  private fallback(identity: ToxicIdentity): string {
    const topFinding = identity.factors[0];
    return `${identity.name} has a risk score of ${identity.riskScore}/100 based on ${identity.factors.length} matched rules across ${identity.platforms.join(', ')}. The leading concern is ${topFinding?.title ?? 'excessive access'}. ${topFinding?.businessImpact ?? 'A compromise could affect high-value resources.'} Recommended first action: ${topFinding?.remediation ?? 'remove unnecessary permissions and require just-in-time elevation.'}`;
  }
}
