import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { RiskService } from '../risk/risk.service';
import { ExecutivePostureTrend } from '../risk/risk.types';
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
    thirtyDayTrend: ExecutivePostureTrend['summary'];
  };
}

@Injectable()
export class CopilotService {
  constructor(
    private readonly config: ConfigService,
    private readonly toxicAccessService: ToxicAccessService,
    private readonly riskService: RiskService,
  ) {}

  async ask(question: string, identityId?: string): Promise<CopilotAnswer> {
    const identity = identityId
      ? await this.toxicAccessService.evaluateIdentity(identityId)
      : (await this.toxicAccessService.listConflictedIdentities())[0];
    if (!identity) {
      throw new Error('No identity with a toxic access conflict is available');
    }
    const trend = await this.riskService.getExecutiveTrend(30);

    const model = this.config.get<string>('OLLAMA_MODEL', 'llama3:8b-instruct-q4_K_M');
    const baseUrl = this.config.get<string>('OLLAMA_BASE_URL', 'http://127.0.0.1:11434');
    const evidence = {
      conflicts: identity.summary.total,
      criticalConflicts: identity.summary.critical,
      platforms: identity.summary.affectedPlatforms,
      thirtyDayTrend: trend.summary,
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
                'You are UnoSecur Copilot. Use only the supplied evidence for identity findings. Be concise, explain attack paths and business impact, and recommend specific least-privilege remediation. You may also teach users how to use the PID Visual Rule Builder: define two or more AND conditions, use comma-separated permissions as OR alternatives, select User/NHI scope, add platform/resource constraints, test against current evidence, save a draft, and publish only after review. Never invent permissions, affected assets, or compliance claims.',
            },
            {
              role: 'user',
              content: `${question}\n\nIdentity evidence:\n${JSON.stringify(
                identity,
              )}\n\n30-day posture trend:\n${JSON.stringify(trend.summary)}`,
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
        answer: this.fallback(question, identity, trend),
        identityId: identity.identityId,
        model,
        source: 'deterministic-fallback',
        evidence,
      };
    }
  }

  private fallback(
    question: string,
    identity: ToxicAccessEvaluation,
    trend: ExecutivePostureTrend,
  ): string {
    const topConflict = identity.conflicts[0];
    const normalizedQuestion = question.toLowerCase();
    if (
      normalizedQuestion.includes('create my own') ||
      normalizedQuestion.includes('define my own') ||
      normalizedQuestion.includes('create a rule') ||
      normalizedQuestion.includes('define a rule') ||
      normalizedQuestion.includes('custom rule') ||
      normalizedQuestion.includes('visual rule')
    ) {
      return 'Open Rule builder from the left navigation. Name the dangerous capability, choose its category and severity, select whether it applies to Users, Service Accounts, or Workloads, then add at least two permission conditions. Add business impact, remediation, and control mappings. Select Test against identities to validate the rule against current evidence, save it as a draft, and publish it only after review.';
    }
    if (
      normalizedQuestion.includes('and or') ||
      normalizedQuestion.includes('and/or') ||
      normalizedQuestion.includes('conditions work') ||
      normalizedQuestion.includes('permission alternatives')
    ) {
      return 'Every condition block in the Visual Rule Builder is joined with AND, so an identity must satisfy every block. Permissions separated by commas inside one block are OR alternatives, so any listed permission can satisfy that condition. Example: cloudtrail:StopLogging AND (s3:DeleteObject OR s3:DeleteBucket).';
    }
    if (
      normalizedQuestion.includes('test a rule') ||
      normalizedQuestion.includes('test before') ||
      normalizedQuestion.includes('preview')
    ) {
      return 'Select Test against identities before saving. PID evaluates the unsaved rule against current effective-access evidence and shows affected identities, identity type, matched permissions, and matched-grant count. Previewing is read-only and does not add the rule to continuous detection.';
    }
    if (
      normalizedQuestion.includes('publish') ||
      normalizedQuestion.includes('draft') ||
      normalizedQuestion.includes('approval')
    ) {
      return 'Save the rule as a draft after its evidence preview is satisfactory. Drafts remain isolated from live detection. Publishing adds the versioned rule to continuous evaluation. In production, publication should require maker-checker approval, RBAC, and a recorded rule owner.';
    }
    if (
      normalizedQuestion.includes('scope a rule') ||
      normalizedQuestion.includes('platform or resource') ||
      normalizedQuestion.includes('resource scope')
    ) {
      return 'Set a platform on each condition when the permission belongs to a specific control plane. Add an optional resource pattern to limit matching to a resource or namespace; * is supported as a wildcard. Use Minimum platforms when the combination must span two or more systems.';
    }
    if (
      normalizedQuestion.includes('users, service accounts') ||
      normalizedQuestion.includes('identity type') ||
      normalizedQuestion.includes('apply to')
    ) {
      return 'Choose Users for human identities, Service Accounts for persistent machine identities, and Workloads for runtime or federated NHIs. Select every applicable type, but narrow the scope when the business process or permission semantics differ between people and automation.';
    }
    if (
      normalizedQuestion.includes('business impact') ||
      normalizedQuestion.includes('remediation should') ||
      normalizedQuestion.includes('control mapping')
    ) {
      return 'Business impact should state what an attacker or insider could accomplish with the full combination. Remediation should name the specific permission separation, approval, JIT, or immutable control that breaks it. Add only control mappings supported by the rule evidence, such as NIST AC-5 for separation of duties or AC-6 for least privilege.';
    }
    if (normalizedQuestion.includes('30 day') || normalizedQuestion.includes('trend')) {
      const direction = trend.summary.toxicIdentityChange <= 0 ? 'reduced' : 'increased';
      return `Over the last 30 days, toxic identities ${direction} by ${Math.abs(
        trend.summary.toxicIdentityChangePercent,
      )}%. ${trend.summary.conflictsRemediated} conflicts were remediated, with ${
        trend.summary.remediationEfficiency
      }% remediation efficiency and a net conflict movement of ${trend.summary.netConflictChange}.`;
    }
    if (normalizedQuestion.includes('rule')) {
      return `${identity.displayName} matched ${identity.conflicts.length} deterministic rules: ${identity.conflicts
        .map(({ ruleId, title }) => `${ruleId} (${title})`)
        .join('; ')}.`;
    }
    if (
      normalizedQuestion.includes('remove') ||
      normalizedQuestion.includes('simulate') ||
      normalizedQuestion.includes('privilege')
    ) {
      const candidate = topConflict?.evidence[0]?.permission;
      return candidate
        ? `Simulate removing ${candidate} first. It is verified evidence for ${topConflict.title}. ${topConflict.remediation}`
        : 'No verified privilege-removal candidate is available for this identity.';
    }
    if (normalizedQuestion.includes('nhi') || normalizedQuestion.includes('non-human')) {
      const permissions = [
        ...new Set(
          identity.conflicts.flatMap(({ evidence }) =>
            evidence.map(({ permission }) => permission),
          ),
        ),
      ];
      return `${identity.displayName} is a ${identity.identityType
        .replace('_', ' ')
        .toLowerCase()} with ${identity.summary.total} toxic combinations. Its verified risky actions include ${permissions
        .slice(0, 5)
        .join(', ')}.`;
    }
    return `${identity.displayName} has ${identity.summary.total} deterministic entitlement conflict${
      identity.summary.total === 1 ? '' : 's'
    } across ${identity.summary.affectedPlatforms.join(', ')}. The leading conflict is ${
      topConflict?.title ?? 'excessive combined access'
    }. ${
      topConflict?.businessImpact ?? 'A compromise could cross multiple control planes.'
    } Recommended first action: ${
      topConflict?.remediation ??
      'remove one side of the conflict and require independent approval.'
    }`;
  }
}
