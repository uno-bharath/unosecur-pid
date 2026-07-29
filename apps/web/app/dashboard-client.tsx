'use client';

import {
  Activity,
  Bot,
  Cloud,
  GitBranch,
  RefreshCw,
  Search,
  ShieldAlert,
  Users,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

interface ToxicIdentity {
  id: string;
  name: string;
  type: string;
  department: string;
  riskScore: number;
  confidence: number;
  platforms: string[];
  factors: Array<{ title: string }>;
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

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000/api';

export default function DashboardClient() {
  const [summary, setSummary] = useState<RiskSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadSummary = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${apiUrl}/risk/summary`);
      if (!response.ok) throw new Error(`API returned ${response.status}`);
      setSummary((await response.json()) as RiskSummary);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Risk API is unavailable');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadSummary();
  }, [loadSummary]);

  const topIdentity = summary?.topIdentities[0];
  const metrics = summary
    ? [
        {
          label: 'Enterprise risk',
          value: String(summary.enterpriseRiskScore),
          suffix: '/100',
          icon: ShieldAlert,
          tone: 'critical',
        },
        {
          label: 'Critical identities',
          value: String(summary.criticalIdentities),
          suffix: '',
          icon: Users,
          tone: 'warning',
        },
        {
          label: 'Attack paths',
          value: String(summary.attackPaths),
          suffix: '',
          icon: GitBranch,
          tone: 'accent',
        },
        {
          label: 'Identities scanned',
          value: summary.identitiesScanned.toLocaleString(),
          suffix: '',
          icon: Activity,
          tone: 'neutral',
        },
      ]
    : [];

  return (
    <main>
      <aside>
        <div className="brand">
          <span>U</span>
          <div>
            UnoSecur<small>IDENTITY COPILOT</small>
          </div>
        </div>
        <nav>
          <a className="active" href="#">
            <Activity size={18} /> Overview
          </a>
          <a href="#">
            <Users size={18} /> Identities
          </a>
          <a href="#">
            <ShieldAlert size={18} /> Findings <b>{summary?.findings ?? '–'}</b>
          </a>
          <a href="#">
            <GitBranch size={18} /> Attack paths
          </a>
          <a href="#">
            <Cloud size={18} /> Cloud coverage
          </a>
          <a href="#">
            <Bot size={18} /> AI Copilot
          </a>
        </nav>
        <div className="environment">
          <i /> Local AI configured<small>Ollama · qwen3:4b</small>
        </div>
      </aside>

      <section className="content">
        <header>
          <div>
            <p>SECURITY POSTURE</p>
            <h1>Good evening, Security Team</h1>
            <span>Live evidence from the deterministic identity risk engine.</span>
          </div>
          <div className="search">
            <Search size={18} />
            <span>Search identities, findings…</span>
            <kbd>⌘ K</kbd>
          </div>
        </header>

        {loading && (
          <div className="state-banner loading">
            <RefreshCw size={16} /> Loading risk evidence from the API…
          </div>
        )}
        {error && (
          <div className="state-banner error">
            <span>Risk API unavailable: {error}. Start the API and database, then retry.</span>
            <button onClick={() => void loadSummary()}>Retry</button>
          </div>
        )}
        {!loading && !error && summary?.topIdentities.length === 0 && (
          <div className="state-banner empty">
            No identities have been evaluated. Seed the database and run a risk scan.
          </div>
        )}

        {summary && (
          <>
            <div className="metrics">
              {metrics.map(({ label, value, suffix, icon: Icon, tone }) => (
                <article className={`metric ${tone}`} key={label}>
                  <div>
                    <span>{label}</span>
                    <Icon size={19} />
                  </div>
                  <strong>
                    {value}
                    <small>{suffix}</small>
                  </strong>
                  <p>
                    {label === 'Enterprise risk'
                      ? 'Calculated from matched rules'
                      : 'Live API data'}
                  </p>
                </article>
              ))}
            </div>

            <div className="grid">
              <article className="panel toxic">
                <div className="panel-title">
                  <div>
                    <p>PRIORITY QUEUE</p>
                    <h2>Toxic identities</h2>
                  </div>
                  <span className="coverage">{summary.platformCoverage.join(' · ')}</span>
                </div>
                {summary.topIdentities.map((identity) => (
                  <div className="identity" key={identity.id}>
                    <div className="avatar">{identity.name.slice(0, 2).toUpperCase()}</div>
                    <div className="identity-copy">
                      <strong>{identity.name}</strong>
                      <small>
                        {identity.department} · {identity.type}
                      </small>
                      <span>{identity.factors[0]?.title ?? 'No toxic combination detected'}</span>
                    </div>
                    <div className="platforms">{identity.platforms.join(' · ')}</div>
                    <div className="score">
                      {identity.riskScore}
                      <small>RISK</small>
                    </div>
                  </div>
                ))}
              </article>

              <article className="panel copilot">
                <div className="panel-title">
                  <div>
                    <p>EVIDENCE SUMMARY</p>
                    <h2>
                      <Bot size={20} /> Investigation context
                    </h2>
                  </div>
                  <i />
                </div>
                {topIdentity && (
                  <>
                    <div className="prompt">Why is {topIdentity.name} a toxic identity?</div>
                    <div className="answer">
                      <strong>
                        {topIdentity.factors.length} matched rules produce a risk score of{' '}
                        {topIdentity.riskScore}.
                      </strong>
                      <p>
                        Evidence spans {topIdentity.platforms.join(', ')} with a confidence of{' '}
                        {topIdentity.confidence}%.
                      </p>
                      <ul>
                        <li>
                          Affects {topIdentity.blastRadius.accounts} accounts and{' '}
                          {topIdentity.blastRadius.clusters} clusters
                        </li>
                        <li>
                          Exposes {topIdentity.blastRadius.secrets} secrets and{' '}
                          {topIdentity.blastRadius.databases} databases
                        </li>
                        <li>Top finding: {topIdentity.factors[0]?.title}</li>
                      </ul>
                    </div>
                  </>
                )}
                <button className="ask" disabled>
                  Live Ollama explanation arrives in Phase 4 <span>→</span>
                </button>
              </article>

              {topIdentity && (
                <article className="panel path">
                  <div className="panel-title">
                    <div>
                      <p>CRITICAL PATH</p>
                      <h2>Identity → high-value resource</h2>
                    </div>
                    <span className="confidence">{topIdentity.confidence}% confidence</span>
                  </div>
                  <div className="nodes">
                    {topIdentity.attackPath.map((node, index) => (
                      <div
                        className={
                          index === 0 || index === topIdentity.attackPath.length - 1
                            ? 'node danger'
                            : 'node'
                        }
                        key={`${node}-${index}`}
                      >
                        <span>{node}</span>
                        {index < topIdentity.attackPath.length - 1 && <b>→</b>}
                      </div>
                    ))}
                  </div>
                </article>
              )}
            </div>
          </>
        )}
      </section>
    </main>
  );
}
