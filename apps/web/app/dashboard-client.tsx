'use client';

import {
  Activity,
  Bell,
  Bot,
  Check,
  ChevronRight,
  Cloud,
  GitBranch,
  LoaderCircle,
  RefreshCw,
  Search,
  Send,
  Settings,
  ShieldAlert,
  SlidersHorizontal,
  Sparkles,
  Users,
  X,
  Zap,
} from 'lucide-react';
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AttackPathGraph } from './components/attack-path-graph';
import { ExecutivePostureTrend, ExecutiveTrendChart } from './components/executive-trend-chart';
import { VisualRuleBuilder } from './components/visual-rule-builder';

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
  identityType: 'HUMAN' | 'SERVICE_ACCOUNT' | 'WORKLOAD';
  provider: string;
  evaluatedAt: string;
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
type WorkspaceView =
  'overview' | 'identities' | 'conflicts' | 'rule-builder' | 'attack-paths' | 'coverage';
type IdentityTypeFilter = 'all' | 'HUMAN' | 'NHI';

function identityTypeLabel(type?: string): string {
  if (!type) return 'Identity';
  return type === 'HUMAN' || type === 'Human' ? 'User' : 'NHI';
}

const connectorGuides: Record<
  string,
  { title: string; description: string; requirements: string[]; steps: string[] }
> = {
  AWS: {
    title: 'AWS IAM adapter',
    description: 'Collect effective IAM grants, role trust and resource access across accounts.',
    requirements: ['AWS account ID', 'Read-only cross-account IAM role', 'External ID'],
    steps: [
      'Create the UnoSecur read-only discovery role from the provided policy.',
      'Add the PID collector account to the role trust policy with an External ID.',
      'Enter the role ARN and validate connectivity before enabling synchronization.',
    ],
  },
  GCP: {
    title: 'Google Cloud IAM adapter',
    description: 'Resolve principals, groups, service accounts and inherited project permissions.',
    requirements: ['Organization or project ID', 'Service account JSON', 'Cloud Asset Viewer role'],
    steps: [
      'Create a dedicated service account for permission discovery.',
      'Grant Cloud Asset Viewer and Organization Viewer at the required scope.',
      'Upload the credential securely and run the connection test.',
    ],
  },
  AZURE: {
    title: 'Azure / Entra adapter',
    description: 'Discover Entra identities and effective Azure RBAC assignments.',
    requirements: ['Tenant ID', 'Client ID', 'Client secret or certificate', 'Reader permissions'],
    steps: [
      'Register an Entra application for PID discovery.',
      'Grant directory read and Azure subscription Reader permissions.',
      'Provide tenant credentials and validate each target subscription.',
    ],
  },
  GITHUB: {
    title: 'GitHub adapter',
    description: 'Evaluate organization roles, repository administration and Actions access.',
    requirements: ['GitHub organization', 'GitHub App ID', 'Private key'],
    steps: [
      'Create a GitHub App with read-only organization and repository permissions.',
      'Install it on the organizations and repositories in scope.',
      'Enter the App credentials and verify repository discovery.',
    ],
  },
  KUBERNETES: {
    title: 'Kubernetes RBAC adapter',
    description: 'Resolve subjects, bindings, service accounts and effective cluster permissions.',
    requirements: ['Cluster endpoint', 'Read-only service account token', 'CA certificate'],
    steps: [
      'Apply the PID discovery ClusterRole and ServiceAccount manifest.',
      'Provide the API endpoint, token and certificate authority data.',
      'Test access and enable the RBAC synchronization interval.',
    ],
  },
};

const platformLogoFiles: Record<string, string> = {
  AWS: 'aws.svg',
  AMAZON: 'aws.svg',
  GCP: 'gcp.svg',
  GOOGLE: 'gcp.svg',
  'GOOGLE CLOUD': 'gcp.svg',
  AZURE: 'azure.svg',
  ENTRA: 'azure.svg',
  MICROSOFT: 'azure.svg',
  GITHUB: 'github.svg',
  KUBERNETES: 'kubernetes.svg',
  K8S: 'kubernetes.svg',
  VAULT: 'vault.svg',
  HASHICORP: 'vault.svg',
  OKTA: 'okta.svg',
};

function platformLogoSrc(platform: string): string {
  const key = platform.trim().toUpperCase();
  const file = platformLogoFiles[key] ?? 'cloud.svg';
  return `/connectors/${file}`;
}

function PlatformLogo({ platform, size = 18 }: { platform: string; size?: number }) {
  return (
    <img
      src={platformLogoSrc(platform)}
      alt=""
      aria-hidden
      className="platform-logo"
      width={size}
      height={size}
      title={platform}
    />
  );
}

const workspaceCopy: Record<
  WorkspaceView,
  { eyebrow: string; title: string; description: string }
> = {
  overview: {
    eyebrow: 'PRIVILEGE INTELLIGENCE',
    title: 'Privilege Intelligence Command Center',
    description: 'See enterprise entitlement conflicts, affected identities, and control planes.',
  },
  identities: {
    eyebrow: 'IDENTITY EXPLORER',
    title: 'Effective Access by Identity',
    description: 'Investigate human and machine identities with evidence-backed privilege context.',
  },
  conflicts: {
    eyebrow: 'CONFLICT CATALOGUE',
    title: 'Dangerous Privilege Combinations',
    description: 'Review deterministic conflicts and the permissions that complete each pattern.',
  },
  'rule-builder': {
    eyebrow: 'POLICY AUTHORING',
    title: 'Visual Toxic-Combination Builder',
    description:
      'Create, test, and publish organization-specific privilege rules without editing code.',
  },
  'attack-paths': {
    eyebrow: 'ACCESS PATHS',
    title: 'Privilege Path Investigation',
    description: 'Trace inherited and cross-platform access to high-value enterprise resources.',
  },
  coverage: {
    eyebrow: 'CONNECTED PLATFORMS',
    title: 'Connected Platforms',
    description: 'Understand where PID currently evaluates privilege combinations and evidence.',
  },
};

export default function DashboardClient() {
  const [summary, setSummary] = useState<RiskSummary | null>(null);
  const [accessEvaluations, setAccessEvaluations] = useState<ToxicAccessEvaluation[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [severity, setSeverity] = useState<(typeof severities)[number]>('all');
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState<CopilotAnswer | null>(null);
  const [asking, setAsking] = useState(false);
  const [simulation, setSimulation] = useState<ToxicAccessSimulation | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [activeView, setActiveView] = useState<WorkspaceView>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [ruleFilter, setRuleFilter] = useState<string | null>(null);
  const [identityTypeFilter, setIdentityTypeFilter] = useState<IdentityTypeFilter>('all');
  const [connectorPlatform, setConnectorPlatform] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [trendRange, setTrendRange] = useState(30);
  const [postureTrend, setPostureTrend] = useState<ExecutivePostureTrend | null>(null);
  const [trendLoading, setTrendLoading] = useState(true);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const selectWorkspaceView = useCallback((view: WorkspaceView) => {
    setActiveView(view);
    const target = view === 'overview' ? '/' : `/?view=${view}`;
    window.history.pushState({ view }, '', target);
  }, []);

  const loadSummary = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    if (!silent) setError(null);
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
      setLastUpdated(new Date());
      setSelectedId(
        (current) => current ?? evaluations[0]?.identityId ?? next.topIdentities[0]?.id ?? null,
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Risk API is unavailable');
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  const loadTrend = useCallback(async (days = trendRange) => {
    setTrendLoading(true);
    try {
      const response = await fetch(`${apiUrl}/risk/executive-trend?days=${days}`);
      if (!response.ok) throw new Error(`Trend API returned ${response.status}`);
      setPostureTrend((await response.json()) as ExecutivePostureTrend);
    } catch {
      setPostureTrend(null);
    } finally {
      setTrendLoading(false);
    }
  }, [trendRange]);

  const refreshInFlight = useRef(false);
  const refreshLiveData = useCallback(async () => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    setRefreshing(true);
    setError(null);
    try {
      const [summaryResponse, accessResponse, trendResponse] = await Promise.all([
        fetch(`${apiUrl}/risk/summary`, { cache: 'no-store' }),
        fetch(`${apiUrl}/toxic-access/identities`, { cache: 'no-store' }),
        fetch(`${apiUrl}/risk/executive-trend?days=${trendRange}`, { cache: 'no-store' }),
      ]);
      if (!summaryResponse.ok) throw new Error(`Identity API returned ${summaryResponse.status}`);
      if (!accessResponse.ok) throw new Error(`Toxic Access API returned ${accessResponse.status}`);
      const next = (await summaryResponse.json()) as RiskSummary;
      const evaluations = (await accessResponse.json()) as ToxicAccessEvaluation[];
      setSummary(next);
      setAccessEvaluations(evaluations);
      setLastUpdated(new Date());
      setSelectedId(
        (current) => current ?? evaluations[0]?.identityId ?? next.topIdentities[0]?.id ?? null,
      );
      if (trendResponse.ok) {
        setPostureTrend((await trendResponse.json()) as ExecutivePostureTrend);
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Refresh failed');
    } finally {
      refreshInFlight.current = false;
      setRefreshing(false);
    }
  }, [trendRange]);

  useEffect(() => {
    void loadSummary();
    const interval = window.setInterval(() => void loadSummary(true), 15_000);
    return () => window.clearInterval(interval);
  }, [loadSummary]);

  useEffect(() => {
    void loadTrend();
  }, [loadTrend]);

  useEffect(() => {
    const focusSearch = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', focusSearch);
    return () => window.removeEventListener('keydown', focusSearch);
  }, []);

  useEffect(() => {
    const syncViewFromLocation = () => {
      const candidate = new URLSearchParams(window.location.search).get('view');
      if (
        candidate === 'identities' ||
        candidate === 'conflicts' ||
        candidate === 'rule-builder' ||
        candidate === 'attack-paths' ||
        candidate === 'coverage'
      ) {
        setActiveView(candidate);
      } else {
        setActiveView('overview');
      }
    };

    syncViewFromLocation();
    window.addEventListener('popstate', syncViewFromLocation);
    return () => window.removeEventListener('popstate', syncViewFromLocation);
  }, []);

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
        (conflict) =>
          (severity === 'all' || conflict.severity === severity) &&
          (categoryFilter === 'all' || conflict.category === categoryFilter) &&
          (!ruleFilter || conflict.ruleId === ruleFilter),
      ) ?? [],
    [categoryFilter, ruleFilter, selectedAccess, severity],
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
  const attackPathGraphPaths = useMemo(() => {
    const fromEvidence =
      selectedAccess?.conflicts.flatMap((conflict) =>
        conflict.evidence
          .map(({ accessPath }) => accessPath.filter(Boolean))
          .filter((path) => path.length > 0),
      ) ?? [];
    if (fromEvidence.length > 0) return fromEvidence;
    if (selectedAccessPath.length > 0) return [selectedAccessPath];
    return [];
  }, [selectedAccess, selectedAccessPath]);

  const selectIdentity = (identity: ToxicIdentity) => {
    setSelectedId(identity.id);
    setSelectedNode(null);
    setSimulation(null);
    setAnswer(null);
  };

  const openSearchResult = (evaluation: ToxicAccessEvaluation, conflict?: ToxicAccessConflict) => {
    setSelectedId(evaluation.identityId);
    setSeverity(conflict?.severity ?? 'all');
    setCategoryFilter(conflict?.category ?? 'all');
    setRuleFilter(conflict?.ruleId ?? null);
    setSearchQuery('');
    selectWorkspaceView(conflict ? 'conflicts' : 'identities');
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
        {
          label: 'Toxic conflicts',
          value: totalConflicts,
          Icon: ShieldAlert,
          tone: 'critical',
          target: 'conflicts' as WorkspaceView,
        },
        {
          label: 'Critical conflicts',
          value: criticalConflicts,
          Icon: Users,
          tone: 'critical-strong',
          target: 'conflicts' as WorkspaceView,
          severity: 'critical' as const,
        },
        {
          label: 'Affected platforms',
          value: affectedPlatforms,
          Icon: GitBranch,
          tone: 'accent',
          target: 'coverage' as WorkspaceView,
        },
        {
          label: 'Identities evaluated',
          value: summary.identitiesScanned,
          Icon: Activity,
          tone: 'neutral',
          target: 'identities' as WorkspaceView,
        },
      ]
    : [];
  const viewCopy = workspaceCopy[activeView];
  const ruleCategories = useMemo(() => {
    const grouped = new Map<
      string,
      { category: string; rules: Set<string>; identities: Set<string>; critical: number }
    >();
    accessEvaluations.forEach((evaluation) => {
      evaluation.conflicts.forEach((conflict) => {
        const current = grouped.get(conflict.category) ?? {
          category: conflict.category,
          rules: new Set<string>(),
          identities: new Set<string>(),
          critical: 0,
        };
        current.rules.add(conflict.ruleId);
        current.identities.add(evaluation.identityId);
        if (conflict.severity === 'critical') current.critical += 1;
        grouped.set(conflict.category, current);
      });
    });
    return [...grouped.values()].sort(
      (left, right) => right.identities.size - left.identities.size,
    );
  }, [accessEvaluations]);
  const visibleIdentities = useMemo(
    () =>
      accessEvaluations.filter(
        ({ identityType }) =>
          identityTypeFilter === 'all' ||
          (identityTypeFilter === 'HUMAN' ? identityType === 'HUMAN' : identityType !== 'HUMAN'),
      ),
    [accessEvaluations, identityTypeFilter],
  );
  const searchResults = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) return [];
    return accessEvaluations
      .flatMap((evaluation) => {
        const matchingConflicts = evaluation.conflicts.filter((conflict) =>
          [
            conflict.title,
            conflict.ruleId,
            conflict.category,
            conflict.severity,
            ...conflict.platforms,
            ...conflict.evidence.map(({ permission }) => permission),
          ]
            .join(' ')
            .toLowerCase()
            .includes(query),
        );
        const identityMatches = [
          evaluation.displayName,
          evaluation.identityType,
          evaluation.provider,
        ]
          .join(' ')
          .toLowerCase()
          .includes(query);
        if (!identityMatches && matchingConflicts.length === 0) return [];
        return [
          {
            evaluation,
            conflict: matchingConflicts[0] ?? evaluation.conflicts[0],
          },
        ];
      })
      .slice(0, 8);
  }, [accessEvaluations, searchQuery]);
  const platformConflictCounts = Array.from(
    new Set([
      ...Object.keys(connectorGuides),
      ...accessEvaluations
        .flatMap((evaluation) => evaluation.summary.affectedPlatforms)
        .map((platform) => platform.toUpperCase()),
    ]),
  )
    .map((platform) => ({
      platform,
      conflicts: accessEvaluations.reduce(
        (total, evaluation) =>
          total +
          evaluation.conflicts.filter((conflict) =>
            conflict.platforms.some((item) => item.toUpperCase() === platform),
          ).length,
        0,
      ),
      identities: accessEvaluations.filter((evaluation) =>
        evaluation.summary.affectedPlatforms.some((item) => item.toUpperCase() === platform),
      ).length,
    }))
    .sort((left, right) => right.conflicts - left.conflicts);
  const selectedConnector = connectorPlatform
    ? (connectorGuides[connectorPlatform.toUpperCase()] ?? {
        title: `${connectorPlatform} adapter`,
        description: `Connect ${connectorPlatform} effective permission evidence to PID.`,
        requirements: ['Read-only discovery credentials', 'Target tenant or account scope'],
        steps: [
          'Create a dedicated read-only discovery identity.',
          'Enter the target scope and credentials using secret storage.',
          'Test access and enable scheduled synchronization.',
        ],
      })
    : null;
  const copilotSuggestions =
    activeView === 'rule-builder'
      ? [
          'How do I create my own toxic combination?',
          'How do AND and OR conditions work?',
          'How can I test a rule before publishing?',
          'Should this rule apply to Users, Service Accounts, or Workloads?',
          'How do I scope a rule to a platform or resource?',
          'What business impact and remediation should I enter?',
          'Which control mappings should I add?',
          'What happens after I publish a rule?',
        ]
      : [
          'Why is this identity toxic?',
          'Which privilege should I remove first?',
          'Simulate removing the highest-risk privilege.',
          'Which deterministic rules matched this identity?',
          `What makes this ${identityTypeLabel(selectedAccess?.identityType)} risky?`,
          'Explain the blast radius.',
          'What business impact could this access cause?',
          'Did remediation reduce toxic identities in the last 30 days?',
          'How do I create my own toxic combination?',
        ];

  return (
    <div className="app-shell">
      <header className="app-topbar">
        <div className="topbar-brand">
          <img
            src="/unosecur-logo.png?v=2"
            alt="unosecur"
            className="topbar-logo-image"
            width={144}
            height={38}
          />
        </div>
        <nav className="topbar-nav" aria-label="Product workspaces">
          <button
            type="button"
            className="topbar-link active"
            title="Privilege Intelligence and Detection"
            onClick={() => {
              if (window.location.pathname === '/' && window.location.search === '') {
                window.location.reload();
              } else {
                window.location.assign('/');
              }
            }}
          >
            <ShieldAlert size={15} />
            <span>Privilege Intelligence &amp; Detection</span>
          </button>
        </nav>
        <div className="topbar-actions">
          <button type="button" className="topbar-icon" aria-label="Notifications">
            <Bell size={18} />
          </button>
          <div className="topbar-avatar" aria-label="Signed in user" title="DC">
            DC
          </div>
        </div>
      </header>

      <div className="app-body">
      <aside>
        <nav>
          <button
            className={activeView === 'overview' ? 'active' : ''}
            onClick={() => selectWorkspaceView('overview')}
          >
            <Activity size={18} /> Overview
          </button>
          <button
            className={activeView === 'identities' ? 'active' : ''}
            onClick={() => selectWorkspaceView('identities')}
          >
            <Users size={18} /> Identities
          </button>
          <button
            className={activeView === 'conflicts' ? 'active' : ''}
            onClick={() => selectWorkspaceView('conflicts')}
          >
            <ShieldAlert size={18} /> Rule findings <b>{totalConflicts || '–'}</b>
          </button>
          <button
            className={activeView === 'rule-builder' ? 'active' : ''}
            onClick={() => selectWorkspaceView('rule-builder')}
          >
            <SlidersHorizontal size={18} /> Rule builder
          </button>
          <button
            className={activeView === 'attack-paths' ? 'active' : ''}
            onClick={() => selectWorkspaceView('attack-paths')}
          >
            <GitBranch size={18} /> Attack paths
          </button>
          <button
            className={activeView === 'coverage' ? 'active' : ''}
            onClick={() => selectWorkspaceView('coverage')}
          >
            <Cloud size={18} /> Connected Platforms
          </button>
        </nav>
      </aside>

      <section className={`content view-${activeView}`} id={activeView}>
        <header className="page-header">
          <div>
            <h1>
              {activeView === 'overview' ? 'Welcome back' : viewCopy.title}
            </h1>
            <span>
              {activeView === 'overview'
                ? "Here's an overview of Privilege Intelligence & Detection"
                : viewCopy.description}
            </span>
          </div>
          <div className="search-shell">
            <label className="search">
              <Search size={18} />
              <input
                aria-label="Search identities, rules, permissions and platforms"
                onChange={(event) => setSearchQuery(event.target.value)}
                placeholder="Search identities, rules, permissions…"
                ref={searchInputRef}
                value={searchQuery}
              />
              <kbd>⌘ K</kbd>
            </label>
            {searchQuery.trim() && (
              <div className="search-results">
                {searchResults.map(({ evaluation, conflict }) => (
                  <button
                    key={`${evaluation.identityId}-${conflict?.ruleId ?? 'identity'}`}
                    onClick={() => openSearchResult(evaluation, conflict)}
                  >
                    <span>
                      <strong>{evaluation.displayName}</strong>
                      <small>
                        {identityTypeLabel(evaluation.identityType)} · {evaluation.provider}
                      </small>
                    </span>
                    <span>
                      {conflict?.title ?? 'Identity profile'}
                      <small>{conflict?.ruleId ?? 'View effective access'}</small>
                    </span>
                    <ChevronRight size={16} />
                  </button>
                ))}
                {searchResults.length === 0 && <p>No matching identity, rule or permission.</p>}
              </div>
            )}
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

        {activeView === 'rule-builder' && (
          <VisualRuleBuilder onRulesChanged={() => void loadSummary()} />
        )}

        {activeView !== 'rule-builder' && summary && selectedIdentity && (
          <>
            <div className={`metrics ${activeView === 'overview' ? 'overview-metrics' : ''}`}>
              {metrics.map(
                (
                  { label, value, Icon: MetricIcon, tone, target, severity: targetSeverity },
                  index,
                ) => {
                  return (
                    <button
                      className={`metric ${tone}`}
                      key={label}
                      style={{ animationDelay: `${index * 70}ms` }}
                      onClick={() => {
                        if (target === 'conflicts') setSeverity(targetSeverity ?? 'all');
                        setRuleFilter(null);
                        selectWorkspaceView(target);
                      }}
                    >
                      <div>
                        <span>{label}</span>
                        <MetricIcon size={19} />
                      </div>
                      <strong>{value}</strong>
                      <p>
                        {label === 'Toxic conflicts'
                          ? 'Deterministic entitlement evidence'
                          : `Open ${target.replace('-', ' ')}`}
                      </p>
                      {activeView === 'overview' && (
                        <em className="metric-cta">
                          Explore <ChevronRight size={14} />
                        </em>
                      )}
                    </button>
                  );
                },
              )}
            </div>

            {activeView === 'overview' && (
              <>
                <section
                  className={`pid-intelligence ${refreshing ? 'is-refreshing' : ''}`}
                  aria-label="Privilege Intelligence and Detection"
                >
                  <div className="pid-integrations">
                    <div className="pid-section-heading">
                      <h3>Platform coverage</h3>
                      <button
                        type="button"
                        className="text-link"
                        onClick={() => selectWorkspaceView('coverage')}
                      >
                        Manage <ChevronRight size={14} />
                      </button>
                    </div>
                    <div className="pid-integration-list">
                      {platformConflictCounts.slice(0, 6).map(({ platform, conflicts, identities }) => {
                        const maxConflicts = Math.max(
                          ...platformConflictCounts.map((item) => item.conflicts),
                          1,
                        );
                        return (
                          <button
                            key={platform}
                            className={`pid-integration-card ${conflicts > 0 ? 'has-risk' : ''}`}
                            onClick={() => {
                              setConnectorPlatform(platform);
                              selectWorkspaceView('coverage');
                            }}
                          >
                            <span className="pid-platform-icon">
                              <PlatformLogo platform={platform} size={18} />
                            </span>
                            <span className="pid-platform-copy">
                              <strong>{platform}</strong>
                              <small>
                                {conflicts > 0
                                  ? `${conflicts} conflicts · ${identities} identities`
                                  : 'Connected · no conflicts'}
                              </small>
                              <span
                                className="pid-platform-bar"
                                aria-hidden
                              >
                                <i style={{ width: `${Math.max((conflicts / maxConflicts) * 100, 6)}%` }} />
                              </span>
                            </span>
                            <span className={conflicts > 0 ? 'status-hot' : 'status-ok'} />
                          </button>
                        );
                      })}
                    </div>
                    <div className="pid-flow-graphic" aria-hidden />
                  </div>
                  <div className="pid-orb-panel">
                    <h3>Privilege Intelligence &amp; Detection</h3>
                    <button
                      type="button"
                      className="pid-orb"
                      aria-label={`${totalConflicts} toxic conflicts — investigate findings`}
                      onClick={() => selectWorkspaceView('conflicts')}
                    >
                      <div className="pid-orb-ring" aria-hidden />
                      <div className="pid-orb-particles" aria-hidden />
                      <div className="pid-orb-core">
                        <strong>{totalConflicts}</strong>
                        <span>Toxic conflicts</span>
                      </div>
                    </button>
                    <div className="pid-stat-chips">
                      <button
                        type="button"
                        className="pid-chip critical"
                        onClick={() => {
                          setSeverity('critical');
                          selectWorkspaceView('conflicts');
                        }}
                      >
                        <b>{criticalConflicts}</b>
                        <span>Critical</span>
                      </button>
                      <button
                        type="button"
                        className="pid-chip platforms"
                        onClick={() => selectWorkspaceView('coverage')}
                      >
                        <b>{affectedPlatforms}</b>
                        <span>Platforms</span>
                      </button>
                      <button
                        type="button"
                        className="pid-chip identities"
                        onClick={() => selectWorkspaceView('identities')}
                      >
                        <b>{summary.identitiesScanned}</b>
                        <span>Identities</span>
                      </button>
                    </div>
                    <div className="pid-orb-actions">
                      <button
                        type="button"
                        className="primary-action"
                        onClick={() => selectWorkspaceView('conflicts')}
                      >
                        Investigate findings
                      </button>
                      <button
                        type="button"
                        className="secondary-action"
                        onClick={() => selectWorkspaceView('attack-paths')}
                      >
                        View attack paths
                      </button>
                    </div>
                  </div>
                </section>

                <div className="overview-quick-actions" aria-label="Quick actions">
                  {[
                    {
                      label: 'Rule findings',
                      hint: 'Review toxic combinations',
                      Icon: ShieldAlert,
                      action: () => selectWorkspaceView('conflicts'),
                    },
                    {
                      label: 'Attack paths',
                      hint: 'Simulate privilege removal',
                      Icon: GitBranch,
                      action: () => selectWorkspaceView('attack-paths'),
                    },
                    {
                      label: 'Rule builder',
                      hint: 'Author custom toxic rules',
                      Icon: SlidersHorizontal,
                      action: () => selectWorkspaceView('rule-builder'),
                    },
                    {
                      label: 'Refresh live',
                      hint: refreshing ? 'Updating evidence…' : 'Pull latest evaluation',
                      Icon: RefreshCw,
                      action: () => void refreshLiveData(),
                      spinning: refreshing,
                    },
                  ].map(({ label, hint, Icon: ActionIcon, action, spinning }) => (
                    <button
                      key={label}
                      type="button"
                      className={`overview-action-card ${spinning ? 'spinning' : ''}`}
                      onClick={action}
                      disabled={Boolean(spinning)}
                    >
                      <span className="overview-action-icon">
                        <ActionIcon size={18} />
                      </span>
                      <span>
                        <strong>{label}</strong>
                        <small>{hint}</small>
                      </span>
                      <ChevronRight size={16} />
                    </button>
                  ))}
                </div>

                <ExecutiveTrendChart
                  loading={trendLoading}
                  onRangeChange={setTrendRange}
                  range={trendRange}
                  trend={postureTrend}
                />
                <div className="overview-grid">
                  <article className="panel overview-rules">
                    <div className="panel-title">
                      <div>
                        <p>RULE CATEGORIES</p>
                        <h2>Where toxic access is concentrated</h2>
                      </div>
                      <span>Click to investigate</span>
                    </div>
                    <div className="category-list">
                      {ruleCategories.map(({ category, rules, identities, critical }) => {
                        const maxCritical = Math.max(
                          ...ruleCategories.map((item) => item.critical),
                          1,
                        );
                        return (
                          <button
                            key={category}
                            onClick={() => {
                              setCategoryFilter(category);
                              setRuleFilter(null);
                              setSeverity('all');
                              const firstIdentity = accessEvaluations.find((evaluation) =>
                                evaluation.conflicts.some(
                                  (conflict) => conflict.category === category,
                                ),
                              );
                              if (firstIdentity) setSelectedId(firstIdentity.identityId);
                              selectWorkspaceView('conflicts');
                            }}
                          >
                            <span>
                              <strong>{category.replaceAll('_', ' ')}</strong>
                              <small>{rules.size} deterministic rules</small>
                              <span className="category-heat" aria-hidden>
                                <i
                                  style={{
                                    width: `${Math.max((critical / maxCritical) * 100, 8)}%`,
                                  }}
                                />
                              </span>
                            </span>
                            <span>
                              <b>{identities.size}</b> identities
                              <small>{critical} critical matches</small>
                            </span>
                            <ChevronRight size={17} />
                          </button>
                        );
                      })}
                    </div>
                  </article>
                  <article className={`panel live-posture ${refreshing ? 'is-refreshing' : ''}`}>
                    <div className="panel-title">
                      <div>
                        <p>LIVE DETECTION</p>
                        <h2>Current evaluation status</h2>
                      </div>
                      <span className={`live-indicator ${refreshing ? 'active' : ''}`}>
                        <i /> {refreshing ? 'Refreshing now…' : 'Live · click refresh'}
                      </span>
                    </div>
                    <strong key={lastUpdated?.getTime() ?? 0}>{totalConflicts}</strong>
                    <p>identity-to-rule matches across {affectedPlatforms} connected platforms.</p>
                    <div className="live-posture-stats">
                      <div>
                        <b>{criticalConflicts}</b>
                        <span>Critical</span>
                      </div>
                      <div>
                        <b>{summary.identitiesScanned}</b>
                        <span>Scanned</span>
                      </div>
                      <div>
                        <b>{affectedPlatforms}</b>
                        <span>Platforms</span>
                      </div>
                    </div>
                    <small>
                      Last evaluated{' '}
                      {lastUpdated?.toLocaleTimeString() ?? 'when data becomes available'}
                    </small>
                    <button
                      type="button"
                      className={refreshing ? 'refreshing' : ''}
                      aria-busy={refreshing}
                      disabled={refreshing}
                      onClick={() => void refreshLiveData()}
                    >
                      <RefreshCw size={15} aria-hidden />
                      {refreshing ? 'Refreshing…' : 'Refresh now'}
                    </button>
                  </article>
                </div>

                <article className="panel overview-hotspots">
                  <div className="panel-title">
                    <div>
                      <p>PRIORITY HOTSPOTS</p>
                      <h2>Identities needing attention first</h2>
                    </div>
                    <button
                      type="button"
                      className="text-link"
                      onClick={() => selectWorkspaceView('identities')}
                    >
                      View all <ChevronRight size={14} />
                    </button>
                  </div>
                  <div className="hotspot-grid">
                    {summary.topIdentities.slice(0, 4).map((identity) => {
                      const evaluation = accessEvaluations.find(
                        ({ identityId }) => identityId === identity.id,
                      );
                      const conflictCount = evaluation?.summary.total ?? 0;
                      return (
                        <button
                          key={identity.id}
                          type="button"
                          className="hotspot-card"
                          onClick={() => {
                            selectIdentity(identity);
                            selectWorkspaceView('identities');
                          }}
                        >
                          <div className="avatar">{identity.name.slice(0, 2).toUpperCase()}</div>
                          <div className="hotspot-copy">
                            <strong>{identity.name}</strong>
                            <small>
                              {identity.department} · {identityTypeLabel(identity.type)}
                            </small>
                            <span>
                              {evaluation?.conflicts[0]?.title ?? 'No toxic combination detected'}
                            </span>
                          </div>
                          <div className={`hotspot-score ${conflictCount > 2 ? 'hot' : ''}`}>
                            {conflictCount}
                            <small>conflicts</small>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </article>
              </>
            )}

            <div className="workspace-grid">
              <article className="panel identity-list" id="identities">
                <div className="panel-title">
                  <div>
                    <p>
                      {activeView === 'conflicts' ? 'AFFECTED USERS / ROLES' : 'PRIORITY QUEUE'}
                    </p>
                    <h2>
                      {activeView === 'conflicts'
                        ? 'Identities in this category'
                        : 'Priority identities'}
                    </h2>
                  </div>
                  <span>{summary.platformCoverage.length} platforms</span>
                </div>
                <div className="identity-type-filter">
                  {(['all', 'HUMAN', 'NHI'] as IdentityTypeFilter[]).map((type) => (
                    <button
                      className={identityTypeFilter === type ? 'active' : ''}
                      key={type}
                      onClick={() => setIdentityTypeFilter(type)}
                    >
                      {type === 'all' ? 'All' : type === 'HUMAN' ? 'Users' : 'NHI'}
                      <span>
                        {type === 'all'
                          ? accessEvaluations.length
                          : accessEvaluations.filter(({ identityType }) =>
                              type === 'HUMAN'
                                ? identityType === 'HUMAN'
                                : identityType !== 'HUMAN',
                            ).length}
                      </span>
                    </button>
                  ))}
                </div>
                {summary.topIdentities
                  .filter((identity) =>
                    visibleIdentities.some(
                      ({ identityId, conflicts }) =>
                        identityId === identity.id &&
                        (activeView !== 'conflicts' ||
                          categoryFilter === 'all' ||
                          conflicts.some(({ category }) => category === categoryFilter)),
                    ),
                  )
                  .map((identity) => (
                    <button
                      className={`identity ${identity.id === selectedIdentity.id ? 'selected' : ''}`}
                      key={identity.id}
                      onClick={() => selectIdentity(identity)}
                    >
                      <div className="avatar">{identity.name.slice(0, 2).toUpperCase()}</div>
                      <div className="identity-copy">
                        <strong>{identity.name}</strong>
                        <small>
                          {identity.department} · {identityTypeLabel(identity.type)}
                        </small>
                        <span>
                          {accessEvaluations.find(({ identityId }) => identityId === identity.id)
                            ?.conflicts[0]?.title ?? 'No toxic combination detected'}
                        </span>
                      </div>
                      <div className="score conflict-count">
                        {accessEvaluations.find(({ identityId }) => identityId === identity.id)
                          ?.summary.total ?? 0}
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

                {selectedAccess && selectedAccess.identityType !== 'HUMAN' && (
                  <div className="nhi-context">
                    <Bot size={18} />
                    <span>
                      <strong>Non-Human Identity privilege posture</strong>
                      This workload or service identity participates in{' '}
                      {selectedAccess?.summary.total ?? 0} toxic combinations across{' '}
                      {selectedAccess?.summary.affectedPlatforms.length ?? 0} platforms.
                    </span>
                    <span>
                      <strong>Risky actions</strong>
                      {[
                        ...new Set(
                          selectedAccess?.conflicts.flatMap(({ evidence }) =>
                            evidence.map(({ permission }) => permission),
                          ) ?? [],
                        ),
                      ]
                        .slice(0, 3)
                        .join(' · ')}
                    </span>
                  </div>
                )}

                {activeView === 'conflicts' && (
                  <>
                    <div className="rule-category-filter">
                      <button
                        className={categoryFilter === 'all' ? 'active' : ''}
                        onClick={() => {
                          setCategoryFilter('all');
                          setRuleFilter(null);
                        }}
                      >
                        All categories
                      </button>
                      {ruleCategories.map(({ category, identities }) => (
                        <button
                          className={categoryFilter === category ? 'active' : ''}
                          key={category}
                          onClick={() => {
                            setCategoryFilter(category);
                            setRuleFilter(null);
                            const firstIdentity = accessEvaluations.find((evaluation) =>
                              evaluation.conflicts.some(
                                (conflict) => conflict.category === category,
                              ),
                            );
                            if (firstIdentity) setSelectedId(firstIdentity.identityId);
                          }}
                        >
                          {category.replaceAll('_', ' ')}
                          <span>{identities.size}</span>
                        </button>
                      ))}
                    </div>
                    <div className="rule-trace">
                      <span>
                        <strong>Identity / role</strong>
                        {selectedAccess?.displayName} ·{' '}
                        {identityTypeLabel(selectedAccess?.identityType)}
                      </span>
                      <ChevronRight size={15} />
                      <span>
                        <strong>Provider</strong>
                        {selectedAccess?.provider}
                      </span>
                      <ChevronRight size={15} />
                      <span>
                        <strong>Matched rules</strong>
                        {filteredConflicts.length}
                      </span>
                    </div>
                  </>
                )}

                <div className="filter-row">
                  {severities.map((item) => (
                    <button
                      className={severity === item ? 'active' : ''}
                      key={item}
                      onClick={() => {
                        setSeverity(item);
                        setRuleFilter(null);
                      }}
                    >
                      {item}
                    </button>
                  ))}
                  {ruleFilter && (
                    <button className="active" onClick={() => setRuleFilter(null)}>
                      {ruleFilter} <X size={11} />
                    </button>
                  )}
                </div>

                <div className="finding-list">
                  {filteredConflicts.map((conflict) => (
                    <button
                      className="finding"
                      key={conflict.ruleId}
                      onClick={() => {
                        setSelectedNode(conflict.evidence[0]?.accessPath.at(-1) ?? null);
                        selectWorkspaceView('attack-paths');
                      }}
                    >
                      <span className={`severity ${conflict.severity}`}>{conflict.severity}</span>
                      <div>
                        <strong>
                          {conflict.title} <small>{conflict.ruleId}</small>
                        </strong>
                        <p>{conflict.businessImpact}</p>
                        <small>
                          {conflict.category.replaceAll('_', ' ')} ·{' '}
                          {conflict.platforms.join(' → ')} · {conflict.evidence.length} matched
                          permissions
                        </small>
                      </div>
                      <ChevronRight size={16} />
                    </button>
                  ))}
                  {filteredConflicts.length === 0 && (
                    <div className="empty-conflicts">
                      No entitlement conflicts match this filter.
                    </div>
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
                <AttackPathGraph
                  paths={attackPathGraphPaths}
                  selectedNode={selectedNode}
                  onSelectNode={setSelectedNode}
                />
                <div className="path-insight">
                  <Zap size={17} />
                  <span>
                    {selectedNode ?? selectedAccessPath[0] ?? 'Selected node'} is part of an
                    effective-access path contributing to{' '}
                    {selectedAccess?.conflicts[0]?.title ?? 'this investigation'}.
                  </span>
                </div>
              </article>

              <article className="panel simulator">
                <div className="panel-title">
                  <div>
                    <p>WHAT-IF REMEDIATION</p>
                    <h2>
                      Simulate least privilege for {identityTypeLabel(selectedAccess?.identityType)}
                    </h2>
                  </div>
                  <Sparkles size={19} />
                </div>
                <p className="muted">
                  Select a privilege to calculate which toxic paths are prevented and which
                  unrelated access remains. No live access is changed.
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
                    <div>
                      <span>Conflicts resolved</span>
                      <strong className="positive">
                        {simulation.currentConflictCount - simulation.projectedConflictCount}
                      </strong>
                    </div>
                    <p>
                      <Check size={15} />{' '}
                      {simulation.resolvedConflicts.join(', ') || 'No conflict fully resolved'}
                    </p>
                    <section>
                      <strong>Recommended remediation action</strong>
                      <span>
                        Revoke <b>{simulation.removedPermissions.join(', ')}</b>{' '}
                        {simulation.resolvedConflicts.length > 0
                          ? `to resolve ${simulation.resolvedConflicts.length} verified toxic combination${
                              simulation.resolvedConflicts.length === 1 ? '' : 's'
                            } while retaining ${simulation.preservedGrantCount} unrelated grants.`
                          : 'does not fully resolve a toxic combination. Evaluate another matched privilege before submitting a change.'}
                      </span>
                      <small>
                        Control recommendation: {selectedAccess?.conflicts[0]?.remediation}
                      </small>
                    </section>
                  </div>
                )}
              </article>
            </div>

            <article className="panel coverage-panel">
              <div className="panel-title">
                <div>
                  <p>CONNECTED EVIDENCE</p>
                  <h2>Connected Platforms</h2>
                </div>
                <span>{platformConflictCounts.length} active platforms</span>
              </div>
              <div className="coverage-grid">
                {platformConflictCounts.map(({ platform, conflicts, identities }) => (
                  <button
                    className="coverage-item"
                    key={platform}
                    onClick={() => setConnectorPlatform(platform)}
                  >
                    <span className="coverage-logo">
                      <PlatformLogo platform={platform} size={22} />
                    </span>
                    <strong>{platform}</strong>
                    <span>
                      {conflicts > 0 ? `${conflicts} matched conflicts` : 'Ready to configure'}
                    </span>
                    <small>
                      {identities > 0 ? `${identities} affected identities` : 'View requirements'}
                    </small>
                    <Settings size={15} className="coverage-settings" />
                  </button>
                ))}
              </div>
            </article>
          </>
        )}
      </section>
      </div>

      <section
        aria-hidden={!selectedConnector}
        aria-label="Connector configuration requirements"
        className={`connector-drawer ${selectedConnector ? 'open' : ''}`}
      >
        {selectedConnector && (
          <>
            <div className="connector-header">
              <div className="connector-heading">
                {connectorPlatform && (
                  <span className="connector-logo">
                    <PlatformLogo platform={connectorPlatform} size={28} />
                  </span>
                )}
                <div>
                  <p>ADAPTER CONFIGURATION</p>
                  <h2>{selectedConnector.title}</h2>
                </div>
              </div>
              <button
                aria-label="Close connector details"
                onClick={() => setConnectorPlatform(null)}
              >
                <X size={18} />
              </button>
            </div>
            <p>{selectedConnector.description}</p>
            <h3>Required details</h3>
            <ul>
              {selectedConnector.requirements.map((requirement) => (
                <li key={requirement}>
                  <Check size={15} /> {requirement}
                </li>
              ))}
            </ul>
            <h3>Configuration flow</h3>
            <ol>
              {selectedConnector.steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
            <div className="connector-action">
              <Check size={16} /> Configuration requirements ready
            </div>
            <small>
              Credentials are not collected in this demonstration. The production adapter stores
              secrets in the organization vault and validates read-only access.
            </small>
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
        {copilotOpen ? (
          <span className="copilot-orb" aria-hidden="true">
            <X size={23} />
          </span>
        ) : (
          <span className="copilot-robot" aria-hidden="true">
            <span className="robot-head">
              <span className="robot-ear robot-ear-left" />
              <span className="robot-ear robot-ear-right" />
              <span className="robot-screen">
                <span className="robot-prompt">&gt;</span>
                <span className="robot-cursor">_</span>
              </span>
            </span>
            <span className="robot-body">
              <span className="robot-arm robot-arm-left" />
              <span className="robot-arm robot-arm-right" />
              <span className="robot-chest">&gt;_</span>
              <span className="robot-leg robot-leg-left" />
              <span className="robot-leg robot-leg-right" />
            </span>
          </span>
        )}
        {!copilotOpen && (
          <>
            <span className="copilot-spark" aria-hidden="true">
              <Sparkles size={12} />
            </span>
            <span className="copilot-status" aria-hidden="true" />
            <span className="copilot-tooltip" role="tooltip">
              Ask UnoSecur Copilot
              <small>
                {activeView === 'rule-builder'
                  ? 'Design a custom rule'
                  : 'Investigate this identity'}
              </small>
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
            {activeView === 'rule-builder'
              ? 'Ask how to design, test, scope, and publish your own toxic-combination rule.'
              : `Ask about ${selectedIdentity?.name ?? 'a toxic identity'}, its attack path, business impact, or the safest remediation.`}
          </div>
          <div className="suggestions">
            {copilotSuggestions.map((suggestion) => (
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
            placeholder={
              activeView === 'rule-builder'
                ? 'Ask how to define a rule…'
                : 'Ask about this identity…'
            }
            value={question}
          />
          <button aria-label="Send question" disabled={asking || !question.trim()} type="submit">
            <Send size={17} />
          </button>
        </form>
      </section>
    </div>
  );
}
