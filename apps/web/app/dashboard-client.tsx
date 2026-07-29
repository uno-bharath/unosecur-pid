'use client';

import {
  Activity,
  Bot,
  Check,
  ChevronRight,
  Cloud,
  GitBranch,
  LoaderCircle,
  MessageCircle,
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

interface RiskSimulation {
  currentScore: number;
  projectedScore: number;
  scoreReduction: number;
  removedPermissions: string[];
  resolvedFindings: string[];
  remainingFindings: string[];
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
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [severity, setSeverity] = useState<(typeof severities)[number]>('all');
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState<CopilotAnswer | null>(null);
  const [asking, setAsking] = useState(false);
  const [simulation, setSimulation] = useState<RiskSimulation | null>(null);
  const [simulating, setSimulating] = useState(false);

  const loadSummary = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${apiUrl}/risk/summary`);
      if (!response.ok) throw new Error(`API returned ${response.status}`);
      const next = (await response.json()) as RiskSummary;
      setSummary(next);
      setSelectedId((current) => current ?? next.topIdentities[0]?.id ?? null);
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
  const filteredFactors = useMemo(
    () =>
      selectedIdentity?.factors.filter(
        (factor) => severity === 'all' || factor.severity === severity,
      ) ?? [],
    [selectedIdentity, severity],
  );
  const removablePermissions = useMemo(
    () =>
      [
        ...new Set(
          selectedIdentity?.factors.flatMap(({ evidence }) => evidence.matchedPermissions ?? []) ??
            [],
        ),
      ].slice(0, 6),
    [selectedIdentity],
  );

  const selectIdentity = (identity: ToxicIdentity) => {
    setSelectedId(identity.id);
    setSelectedNode(identity.attackPath[0] ?? null);
    setSimulation(null);
    setAnswer(null);
  };

  const runSimulation = async (permission: string) => {
    if (!selectedIdentity) return;
    setSimulating(true);
    try {
      const response = await fetch(`${apiUrl}/risk/identities/${selectedIdentity.id}/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ removePermissions: [permission] }),
      });
      if (!response.ok) throw new Error(`Simulation returned ${response.status}`);
      setSimulation((await response.json()) as RiskSimulation);
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

  const metrics = summary
    ? [
        ['Enterprise risk', String(summary.enterpriseRiskScore), '/100', ShieldAlert, 'critical'],
        ['Critical identities', String(summary.criticalIdentities), '', Users, 'warning'],
        ['Attack paths', String(summary.attackPaths), '', GitBranch, 'accent'],
        ['Identities scanned', String(summary.identitiesScanned), '', Activity, 'neutral'],
      ]
    : [];

  return (
    <main>
      <aside>
        <div className="brand">
          <span>U</span>
          <div>
            unosecur<small>IDENTITY COPILOT</small>
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
            <ShieldAlert size={18} /> Findings <b>{summary?.findings ?? '–'}</b>
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
            <p>SECURITY POSTURE</p>
            <h1>Identity Defense Command Center</h1>
            <span>Evidence-led risk decisions across every connected control plane.</span>
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
                      {label === 'Enterprise risk' ? 'Explainable weighted score' : 'Live API data'}
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
                    <h2>Toxic identities</h2>
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
                      <span>{identity.factors[0]?.title}</span>
                    </div>
                    <div className="score">
                      {identity.riskScore}
                      <small>RISK</small>
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
                    {selectedIdentity.riskScore}
                    <small>RISK</small>
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
                  {filteredFactors.map((factor) => (
                    <div className="finding" key={factor.ruleId}>
                      <span className={`severity ${factor.severity}`}>{factor.severity}</span>
                      <div>
                        <strong>{factor.title}</strong>
                        <p>{factor.justification}</p>
                        <small>
                          {factor.platform} · {factor.mitre}
                        </small>
                      </div>
                    </div>
                  ))}
                </div>
              </article>

              <article className="panel path" id="attack-path">
                <div className="panel-title">
                  <div>
                    <p>INTERACTIVE ATTACK PATH</p>
                    <h2>Identity → high-value resource</h2>
                  </div>
                  <span>{selectedIdentity.confidence}% confidence</span>
                </div>
                <div className="nodes">
                  {selectedIdentity.attackPath.map((node, index) => (
                    <div className="node-wrap" key={`${node}-${index}`}>
                      <button
                        className={`node ${selectedNode === node ? 'selected' : ''} ${
                          index === 0 || index === selectedIdentity.attackPath.length - 1
                            ? 'danger'
                            : ''
                        }`}
                        onClick={() => setSelectedNode(node)}
                      >
                        {node}
                      </button>
                      {index < selectedIdentity.attackPath.length - 1 && <ChevronRight size={16} />}
                    </div>
                  ))}
                </div>
                <div className="path-insight">
                  <Zap size={17} />
                  <span>
                    {selectedNode ?? selectedIdentity.attackPath[0]} participates in a path exposing{' '}
                    {selectedIdentity.blastRadius.secrets} secrets and{' '}
                    {selectedIdentity.blastRadius.databases} databases.
                  </span>
                </div>
              </article>

              <article className="panel simulator">
                <div className="panel-title">
                  <div>
                    <p>WHAT-IF REMEDIATION</p>
                    <h2>Preview risk reduction</h2>
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
                      <span>Projected risk</span>
                      <strong>{simulation.projectedScore}</strong>
                    </div>
                    <div>
                      <span>Reduction</span>
                      <strong className="positive">−{simulation.scoreReduction}</strong>
                    </div>
                    <div>
                      <span>Resolved findings</span>
                      <strong>{simulation.resolvedFindings.length}</strong>
                    </div>
                    <p>
                      <Check size={15} />{' '}
                      {simulation.resolvedFindings.join(', ') || 'No finding fully resolved'}
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
        className={`copilot-launcher ${copilotOpen ? 'open' : ''}`}
        onClick={() => setCopilotOpen((open) => !open)}
      >
        {copilotOpen ? <X size={22} /> : <MessageCircle size={23} />}
        {!copilotOpen && <span>Ask Copilot</span>}
      </button>

      <section className={`copilot-drawer ${copilotOpen ? 'open' : ''}`} aria-hidden={!copilotOpen}>
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
