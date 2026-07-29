'use client';

import {
  Activity,
  Bot,
  Check,
  ChevronRight,
  Cloud,
  GitBranch,
  LoaderCircle,
  RefreshCw,
  Search,
  Send,
  ShieldAlert,
  Sparkles,
  Users,
  X,
  Zap,
} from 'lucide-react';
import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';

type Severity = 'critical' | 'high' | 'medium' | 'low';

interface RiskFactor {
  ruleId: string;
  title: string;
  platform: string;
  severity: Severity;
  justification: string;
  businessImpact: string;
  remediation: string;
  mitre: string;
  nist: string;
  evidence: { matchedPermissions?: string[] };
}

interface ToxicIdentity {
  id: string;
  name: string;
  type: string;
  department: string;
  riskScore: number;
  confidence: number;
  platforms: string[];
  factors: RiskFactor[];
  attackPath: string[];
  blastRadius: { accounts: number; clusters: number; secrets: number; databases: number };
}

interface RiskSummary {
  enterpriseRiskScore: number;
  identitiesScanned: number;
  criticalIdentities: number;
  attackPaths: number;
  findings: number;
  platformCoverage: string[];
  topIdentities: ToxicIdentity[];
}

interface MatchedEntitlement {
  requirementId: string;
  permission: string;
  platform: string;
  resource: string;
  accessPath: string[];
}

interface ToxicAccessConflict {
  ruleId: string;
  title: string;
  category: string;
  severity: Severity;
  businessImpact: string;
  remediation: string;
  platforms: string[];
  evidence: MatchedEntitlement[];
  mappings: { mitre: string[]; nist: string[] };
}

interface ToxicAccessEvaluation {
  identityId: string;
  displayName: string;
  source: string;
  conflicts: ToxicAccessConflict[];
  summary: {
    total: number;
    critical: number;
    high: number;
    affectedPlatforms: string[];
  };
}

interface ToxicAccessSimulation {
  currentConflictCount: number;
  projectedConflictCount: number;
  removedPermissions: string[];
  resolvedConflicts: string[];
  remainingConflicts: string[];
  preservedGrantCount: number;
}

interface CopilotAnswer {
  answer: string;
  source: 'ollama' | 'deterministic-fallback';
  model: string;
}

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000/api';
const severities: Array<'all' | Severity> = ['all', 'critical', 'high', 'medium'];

export default function DashboardClient() {
  const [summary, setSummary] = useState<RiskSummary | null>(null);
  const [accessEvaluations, setAccessEvaluations] = useState<ToxicAccessEvaluation[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [severity, setSeverity] = useState<(typeof severities)[number]>('all');
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState<CopilotAnswer | null>(null);
  const [asking, setAsking] = useState(false);
  const [simulation, setSimulation] = useState<ToxicAccessSimulation | null>(null);
  const [simulating, setSimulating] = useState(false);

  const loadSummary = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [summaryResponse, accessResponse] = await Promise.all([
        fetch(`${apiUrl}/risk/summary`),
        fetch(`${apiUrl}/toxic-access/identities`),
      ]);
      if (!summaryResponse.ok) throw new Error(`Identity API returned ${summaryResponse.status}`);
      if (!accessResponse.ok) throw new Error(`Toxic Access API returned ${accessResponse.status}`);
      const next = (await summaryResponse.json()) as RiskSummary;
      const evaluations = (await accessResponse.json()) as ToxicAccessEvaluation[];
      setSummary(next);
      setAccessEvaluations(evaluations);
      setSelectedId(
        (current) => current ?? evaluations[0]?.identityId ?? next.topIdentities[0]?.id ?? null,
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Risk API is unavailable');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadSummary();
  }, [loadSummary]);

  const selectedIdentity = useMemo(
    () =>
      summary?.topIdentities.find(({ id }) => id === selectedId) ??
      summary?.topIdentities[0] ??
      null,
    [selectedId, summary],
  );
  const selectedAccess = useMemo(
    () => accessEvaluations.find(({ identityId }) => identityId === selectedId) ?? null,
    [accessEvaluations, selectedId],
  );
  const filteredConflicts = useMemo(
    () =>
      selectedAccess?.conflicts.filter(
        (conflict) => severity === 'all' || conflict.severity === severity,
      ) ?? [],
    [selectedAccess, severity],
  );
  const removablePermissions = useMemo(
    () =>
      [
        ...new Set(
          selectedAccess?.conflicts.flatMap(({ evidence }) =>
            evidence.map(({ permission }) => permission),
          ) ?? [],
        ),
      ].slice(0, 6),
    [selectedAccess],
  );
  const selectedAccessPath = useMemo(
    () =>
      selectedAccess?.conflicts[0]?.evidence.flatMap(({ accessPath }) => accessPath) ??
      selectedIdentity?.attackPath ??
      [],
    [selectedAccess, selectedIdentity],
  );

  const selectIdentity = (identity: ToxicIdentity) => {
    setSelectedId(identity.id);
    setSelectedNode(null);
    setSimulation(null);
    setAnswer(null);
  };

  const runSimulation = async (permission: string) => {
    if (!selectedIdentity) return;
    setSimulating(true);
    try {
      const response = await fetch(
        `${apiUrl}/toxic-access/identities/${selectedIdentity.id}/simulate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ removePermissions: [permission] }),
        },
      );
      if (!response.ok) throw new Error(`Simulation returned ${response.status}`);
      setSimulation((await response.json()) as ToxicAccessSimulation);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Simulation failed');
    } finally {
      setSimulating(false);
    }
  };

  const askCopilot = async (event?: FormEvent, suggestedQuestion?: string) => {
    event?.preventDefault();
    const prompt = suggestedQuestion ?? question.trim();
    if (!prompt || !selectedIdentity) return;
    setQuestion(prompt);
    setAsking(true);
    setAnswer(null);
    try {
      const response = await fetch(`${apiUrl}/copilot/ask`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: prompt, identityId: selectedIdentity.id }),
      });
      if (!response.ok) throw new Error(`Copilot returned ${response.status}`);
      setAnswer((await response.json()) as CopilotAnswer);
    } catch (reason) {
      setAnswer({
        answer: reason instanceof Error ? reason.message : 'Copilot is unavailable.',
        source: 'deterministic-fallback',
        model: 'local',
      });
    } finally {
      setAsking(false);
    }
  };

  const totalConflicts = accessEvaluations.reduce(
    (total, evaluation) => total + evaluation.summary.total,
    0,
  );
  const criticalConflicts = accessEvaluations.reduce(
    (total, evaluation) => total + evaluation.summary.critical,
    0,
  );
  const affectedPlatforms = new Set(
    accessEvaluations.flatMap(({ summary: accessSummary }) => accessSummary.affectedPlatforms),
  ).size;
  const metrics = summary
    ? [
        ['Toxic conflicts', String(totalConflicts), '', ShieldAlert, 'critical'],
        ['Critical conflicts', String(criticalConflicts), '', Users, 'warning'],
        ['Affected platforms', String(affectedPlatforms), '', GitBranch, 'accent'],
        ['Identities evaluated', String(summary.identitiesScanned), '', Activity, 'neutral'],
      ]
    : [];

  return (
    <main>
      <aside>
        <div className="brand">
          <span>U</span>
          <div>
            unosecur<small>TOXIC ACCESS INTELLIGENCE</small>
          </div>
        </div>
        <nav>
          <a className="active" href="#overview">
            <Activity size={18} /> Overview
          </a>
          <a href="#identities">
            <Users size={18} /> Identities
          </a>
          <a href="#findings">
            <ShieldAlert size={18} /> Conflicts <b>{totalConflicts || '–'}</b>
          </a>
          <a href="#attack-path">
            <GitBranch size={18} /> Attack paths
          </a>
          <a href="#coverage">
            <Cloud size={18} /> Cloud coverage
          </a>
        </nav>
        <div className="environment">
          <i /> Local AI configured<small>Ollama · llama3:8b</small>
        </div>
      </aside>

      <section className="content" id="overview">
        <header>
          <div>
            <p>ACCESS INTELLIGENCE</p>
            <h1>Toxic Access Command Center</h1>
            <span>Find dangerous entitlement combinations before they are exploited.</span>
          </div>
          <div className="search">
            <Search size={18} />
            <span>Search identities, findings…</span>
            <kbd>⌘ K</kbd>
          </div>
        </header>

        {loading && (
          <div className="state-banner loading">
            <RefreshCw size={16} /> Loading identity evidence…
          </div>
        )}
        {error && (
          <div className="state-banner error">
            <span>{error}</span>
            <button onClick={() => void loadSummary()}>Retry</button>
          </div>
        )}

        {summary && selectedIdentity && (
          <>
            <div className="metrics">
              {metrics.map(([label, value, suffix, Icon, tone]) => {
                const MetricIcon = Icon as typeof Activity;
                return (
                  <article className={`metric ${tone}`} key={String(label)}>
                    <div>
                      <span>{String(label)}</span>
                      <MetricIcon size={19} />
                    </div>
                    <strong>
                      {String(value)}
                      <small>{String(suffix)}</small>
                    </strong>
                    <p>
                      {label === 'Toxic conflicts'
                        ? 'Deterministic entitlement evidence'
                        : 'Live Toxic Access API'}
                    </p>
                  </article>
                );
              })}
            </div>

            <div className="workspace-grid">
              <article className="panel identity-list" id="identities">
                <div className="panel-title">
                  <div>
                    <p>PRIORITY QUEUE</p>
                    <h2>Priority identities</h2>
                  </div>
                  <span>{summary.platformCoverage.length} platforms</span>
                </div>
                {summary.topIdentities.map((identity) => (
                  <button
                    className={`identity ${identity.id === selectedIdentity.id ? 'selected' : ''}`}
                    key={identity.id}
                    onClick={() => selectIdentity(identity)}
                  >
                    <div className="avatar">{identity.name.slice(0, 2).toUpperCase()}</div>
                    <div className="identity-copy">
                      <strong>{identity.name}</strong>
                      <small>
                        {identity.department} · {identity.type}
                      </small>
                      <span>
                        {accessEvaluations.find(({ identityId }) => identityId === identity.id)
                          ?.conflicts[0]?.title ?? 'No toxic combination detected'}
                      </span>
                    </div>
                    <div className="score conflict-count">
                      {accessEvaluations.find(({ identityId }) => identityId === identity.id)?.summary
                        .total ?? 0}
                      <small>CONFLICTS</small>
                    </div>
                    <ChevronRight size={16} />
                  </button>
                ))}
              </article>

              <article className="panel identity-detail" id="findings">
                <div className="detail-heading">
                  <div className="avatar large">
                    {selectedIdentity.name.slice(0, 2).toUpperCase()}
                  </div>
                  <div>
                    <p>IDENTITY INVESTIGATION</p>
                    <h2>{selectedIdentity.name}</h2>
                    <span>
                      {selectedIdentity.department} · {selectedIdentity.platforms.join(' · ')}
                    </span>
                  </div>
                  <div className="score hero-score">
                    {selectedAccess?.summary.total ?? 0}
                    <small>CONFLICTS</small>
                  </div>
                </div>

                <div className="filter-row">
                  {severities.map((item) => (
                    <button
                      className={severity === item ? 'active' : ''}
                      key={item}
                      onClick={() => setSeverity(item)}
                    >
                      {item}
                    </button>
                  ))}
                </div>

                <div className="finding-list">
                  {filteredConflicts.map((conflict) => (
                    <div className="finding" key={conflict.ruleId}>
                      <span className={`severity ${conflict.severity}`}>{conflict.severity}</span>
                      <div>
                        <strong>{conflict.title}</strong>
                        <p>{conflict.businessImpact}</p>
                        <small>
                          {conflict.platforms.join(' → ')} · {conflict.mappings.nist.join(', ')}
                        </small>
                      </div>
                    </div>
                  ))}
                  {filteredConflicts.length === 0 && (
                    <div className="empty-conflicts">No entitlement conflicts match this filter.</div>
                  )}
                </div>
              </article>

              <article className="panel path" id="attack-path">
                <div className="panel-title">
                  <div>
                    <p>INTERACTIVE ATTACK PATH</p>
                    <h2>Identity → high-value resource</h2>
                  </div>
                  <span>{selectedAccess?.source ?? 'demo compatibility'}</span>
                </div>
                <div className="nodes">
                  {selectedAccessPath.map((node, index) => (
                    <div className="node-wrap" key={`${node}-${index}`}>
                      <button
                        className={`node ${selectedNode === node ? 'selected' : ''} ${
                          index === 0 || index === selectedAccessPath.length - 1
                            ? 'danger'
                            : ''
                        }`}
                        onClick={() => setSelectedNode(node)}
                      >
                        {node}
                      </button>
                      {index < selectedAccessPath.length - 1 && <ChevronRight size={16} />}
                    </div>
                  ))}
                </div>
                <div className="path-insight">
                  <Zap size={17} />
                  <span>
                    {selectedNode ?? selectedAccessPath[0]} is part of an effective-access path
                    contributing to {selectedAccess?.conflicts[0]?.title ?? 'this investigation'}.
                  </span>
                </div>
              </article>

              <article className="panel simulator">
                <div className="panel-title">
                  <div>
                    <p>WHAT-IF REMEDIATION</p>
                    <h2>Preview conflict resolution</h2>
                  </div>
                  <Sparkles size={19} />
                </div>
                <p className="muted">
                  Select one permission to model its removal. No live access is changed.
                </p>
                <div className="permission-list">
                  {removablePermissions.map((permission) => (
                    <button
                      disabled={simulating}
                      key={permission}
                      onClick={() => void runSimulation(permission)}
                    >
                      {permission}
                    </button>
                  ))}
                </div>
                {simulation && (
                  <div className="simulation-result">
                    <div>
                      <span>Current conflicts</span>
                      <strong>{simulation.currentConflictCount}</strong>
                    </div>
                    <div>
                      <span>Projected conflicts</span>
                      <strong className="positive">{simulation.projectedConflictCount}</strong>
                    </div>
                    <div>
                      <span>Access preserved</span>
                      <strong>{simulation.preservedGrantCount}</strong>
                    </div>
                    <p>
                      <Check size={15} />{' '}
                      {simulation.resolvedConflicts.join(', ') || 'No conflict fully resolved'}
                    </p>
                  </div>
                )}
              </article>
            </div>
          </>
        )}
      </section>

      <button
        aria-label="Ask UnoSecur Copilot"
        aria-controls="unosecur-copilot"
        aria-expanded={copilotOpen}
        className={`copilot-launcher ${copilotOpen ? 'open' : ''}`}
        onClick={() => setCopilotOpen((open) => !open)}
      >
        <span className="copilot-pulse" aria-hidden="true" />
        <span className="copilot-orb" aria-hidden="true">
          {copilotOpen ? <X size={23} /> : <Bot size={25} />}
        </span>
        {!copilotOpen && (
          <>
            <span className="copilot-spark" aria-hidden="true">
              <Sparkles size={12} />
            </span>
            <span className="copilot-status" aria-hidden="true" />
            <span className="copilot-tooltip" role="tooltip">
              Ask UnoSecur Copilot
              <small>Investigate this identity</small>
            </span>
          </>
        )}
      </button>

      <section
        aria-hidden={!copilotOpen}
        aria-label="UnoSecur Copilot"
        className={`copilot-drawer ${copilotOpen ? 'open' : ''}`}
        id="unosecur-copilot"
      >
        <div className="copilot-header">
          <div className="copilot-mark">
            <Bot size={20} />
          </div>
          <div>
            <strong>UnoSecur Copilot</strong>
            <span>
              <i /> Local · evidence grounded
            </span>
          </div>
          <button aria-label="Close Copilot" onClick={() => setCopilotOpen(false)}>
            <X size={18} />
          </button>
        </div>
        <div className="copilot-body">
          <div className="assistant-message">
            Ask about {selectedIdentity?.name ?? 'a toxic identity'}, its attack path, business
            impact, or the safest remediation.
          </div>
          <div className="suggestions">
            {[
              'Why is this identity toxic?',
              'What should I remove first?',
              'Explain the blast radius.',
            ].map((suggestion) => (
              <button key={suggestion} onClick={() => void askCopilot(undefined, suggestion)}>
                {suggestion}
              </button>
            ))}
          </div>
          {asking && (
            <div className="assistant-message loading-answer">
              <LoaderCircle size={16} /> Analysing verified evidence with Ollama…
            </div>
          )}
          {answer && (
            <div className="assistant-message answer-message">
              <span>{answer.source === 'ollama' ? answer.model : 'Evidence fallback'}</span>
              {answer.answer}
            </div>
          )}
        </div>
        <form className="copilot-input" onSubmit={(event) => void askCopilot(event)}>
          <input
            aria-label="Ask Copilot"
            onChange={(event) => setQuestion(event.target.value)}
            placeholder="Ask about this identity…"
            value={question}
          />
          <button aria-label="Send question" disabled={asking || !question.trim()} type="submit">
            <Send size={17} />
          </button>
        </form>
      </section>
    </main>
  );
}
