'use client';

import {
  Activity,
  Bell,
  Bot,
  Boxes,
  Check,
  ChevronRight,
  Cloud,
  Database,
  GitBranch,
  LoaderCircle,
  KeyRound,
  RefreshCw,
  Radio,
  Search,
  Send,
  Settings,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Users,
  Workflow,
  X,
  Zap,
} from 'lucide-react';
import { FaAws, FaMicrosoft, FaSlack } from 'react-icons/fa';
import {
  SiArgo,
  SiCloudflare,
  SiGithub,
  SiGitlab,
  SiGoogle,
  SiGooglecloud,
  SiJenkins,
  SiKubernetes,
  SiOkta,
  SiPostgresql,
  SiSnowflake,
  SiVault,
} from 'react-icons/si';
import type { IconType } from 'react-icons';
import { VscAzure } from 'react-icons/vsc';
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import { AttackPathDirection, AttackPathGraph } from './components/attack-path-graph';
import {
  ExecutivePostureTrend,
  ExecutiveTrendChart,
  ImmunityWindow,
  toImmunityWindow,
} from './components/executive-trend-chart';
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
  removedAssignments: string[];
  resolvedConflicts: string[];
  remainingConflicts: string[];
  preservedGrantCount: number;
  businessAccessPreservedPercent: number;
  riskReductionPercent: number;
  resolvedCriticalConflicts: number;
  resolvedHighConflicts: number;
  attackPathsDisrupted: number;
  protectedResources: string[];
  controlsImproved: string[];
  affectedPlatformsBefore: string[];
  affectedPlatformsAfter: string[];
  residualSeverity: Severity | 'none';
  securityOutcomes: string[];
}

interface RealtimeCoverageSummary {
  evaluatedAt: string;
  evidenceMode: 'DEMONSTRATION' | 'CONNECTED';
  evidenceSource: string;
  refreshIntervalSeconds: number;
  connectedPlatforms: number;
  availablePlatforms: number;
  identitiesObserved: number;
  entitlementsObserved: number;
  activeConflicts: number;
  connectors: Array<{
    id: string;
    platform: string;
    domain: string;
    status: 'CONNECTED' | 'READY_TO_CONNECT';
    syncMode: string;
    identities: number;
    entitlements: number;
    conflicts: number;
    criticalConflicts: number;
    evaluatedAt: string;
    dataSource: string;
  }>;
  recentEntitlementEvents: Array<{
    id: string;
    observedAt: string;
    platform: string;
    identityId: string;
    displayName: string;
    identityType: 'HUMAN' | 'SERVICE_ACCOUNT' | 'WORKLOAD';
    permission: string;
    resource: string;
    assignment: string;
    createsConflict: boolean;
  }>;
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

type PlatformIconComponent = IconType | typeof Cloud;

const platformIcons: Record<string, { Icon: PlatformIconComponent; color: string }> = {
  AWS: { Icon: FaAws, color: '#ff9900' },
  GCP: { Icon: SiGooglecloud, color: '#4285f4' },
  AZURE: { Icon: VscAzure, color: '#0078d4' },
  GITHUB: { Icon: SiGithub, color: '#24292f' },
  KUBERNETES: { Icon: SiKubernetes, color: '#326ce5' },
  'ENTRA ID': { Icon: FaMicrosoft, color: '#2563eb' },
  OKTA: { Icon: SiOkta, color: '#1662dd' },
  GITLAB: { Icon: SiGitlab, color: '#fc6d26' },
  JENKINS: { Icon: SiJenkins, color: '#d33833' },
  ARGOCD: { Icon: SiArgo, color: '#ef7b4d' },
  VAULT: { Icon: SiVault, color: '#111827' },
  POSTGRESQL: { Icon: SiPostgresql, color: '#4169e1' },
  SNOWFLAKE: { Icon: SiSnowflake, color: '#29b5e8' },
  'GOOGLE WORKSPACE': { Icon: SiGoogle, color: '#4285f4' },
  'MICROSOFT 365': { Icon: FaMicrosoft, color: '#f25022' },
  SERVICENOW: { Icon: Workflow, color: '#2e8b57' },
  SLACK: { Icon: FaSlack, color: '#611f69' },
  CLOUDFLARE: { Icon: SiCloudflare, color: '#f38020' },
};

function PlatformIcon({ platform, compact = false }: { platform: string; compact?: boolean }) {
  const normalized = platform.toUpperCase();
  const fallback =
    connectorGuides[normalized]?.category === 'Data'
      ? Database
      : connectorGuides[normalized]?.category === 'Secrets'
        ? KeyRound
        : connectorGuides[normalized]?.category === 'Supply chain'
          ? Boxes
          : Cloud;
  const { Icon, color } = platformIcons[normalized] ?? { Icon: fallback, color: '#315ddd' };

  return (
    <span
      className={`platform-icon ${compact ? 'compact' : ''}`}
      style={{ '--platform-color': color } as CSSProperties}
      aria-hidden="true"
    >
      <Icon size={compact ? 14 : 19} />
    </span>
  );
}

const connectorGuides: Record<
  string,
  {
    title: string;
    description: string;
    category: 'Cloud' | 'Identity' | 'Kubernetes' | 'Supply chain' | 'Secrets' | 'Data' | 'SaaS';
    requirements: string[];
    evidence: string[];
    steps: string[];
  }
> = {
  AWS: {
    title: 'AWS IAM adapter',
    description: 'Collect effective IAM grants, role trust and resource access across accounts.',
    category: 'Cloud',
    requirements: ['AWS account ID', 'Read-only cross-account IAM role', 'External ID'],
    evidence: [
      'Users, roles and policies',
      'Trust and assume-role paths',
      'Resource-scoped permissions',
    ],
    steps: [
      'Create the UnoSecur read-only discovery role from the provided policy.',
      'Add the PID collector account to the role trust policy with an External ID.',
      'Enter the role ARN and validate connectivity before enabling synchronization.',
    ],
  },
  GCP: {
    title: 'Google Cloud IAM adapter',
    description: 'Resolve principals, groups, service accounts and inherited project permissions.',
    category: 'Cloud',
    requirements: ['Organization or project ID', 'Service account JSON', 'Cloud Asset Viewer role'],
    evidence: [
      'Users, groups and service accounts',
      'Organization, folder and project IAM',
      'Workload identity bindings',
    ],
    steps: [
      'Create a dedicated service account for permission discovery.',
      'Grant Cloud Asset Viewer and Organization Viewer at the required scope.',
      'Upload the credential securely and run the connection test.',
    ],
  },
  AZURE: {
    title: 'Azure / Entra adapter',
    description: 'Discover Entra identities and effective Azure RBAC assignments.',
    category: 'Cloud',
    requirements: ['Tenant ID', 'Client ID', 'Client secret or certificate', 'Reader permissions'],
    evidence: ['Azure RBAC assignments', 'Management-group inheritance', 'Managed identities'],
    steps: [
      'Register an Entra application for PID discovery.',
      'Grant directory read and Azure subscription Reader permissions.',
      'Provide tenant credentials and validate each target subscription.',
    ],
  },
  GITHUB: {
    title: 'GitHub adapter',
    description: 'Evaluate organization roles, repository administration and Actions access.',
    category: 'Supply chain',
    requirements: ['GitHub organization', 'GitHub App ID', 'Private key'],
    evidence: [
      'Organization and repository roles',
      'Actions and environment access',
      'Teams and deploy keys',
    ],
    steps: [
      'Create a GitHub App with read-only organization and repository permissions.',
      'Install it on the organizations and repositories in scope.',
      'Enter the App credentials and verify repository discovery.',
    ],
  },
  KUBERNETES: {
    title: 'Kubernetes RBAC adapter',
    description: 'Resolve subjects, bindings, service accounts and effective cluster permissions.',
    category: 'Kubernetes',
    requirements: [
      'Approved kubeconfig contexts or in-cluster identity',
      'Read-only RBAC',
      'Namespace allowlist',
    ],
    evidence: [
      'Roles, ClusterRoles and bindings',
      'Service accounts and workloads',
      'Pod security and identity federation',
    ],
    steps: [
      'Discover contexts from kubeconfig and explicitly select approved clusters.',
      'Apply the PID read-only ClusterRole and bind the collection identity.',
      'Select namespaces, validate metadata access and enable watch-based updates.',
    ],
  },
  'ENTRA ID': {
    title: 'Microsoft Entra ID adapter',
    description: 'Correlate users, groups, applications, service principals and directory roles.',
    category: 'Identity',
    requirements: [
      'Tenant ID',
      'Application ID',
      'Certificate or vault reference',
      'Directory read permissions',
    ],
    evidence: [
      'Directory roles and groups',
      'Service principals and app roles',
      'Conditional-access context',
    ],
    steps: [
      'Register a read-only Entra application.',
      'Approve minimum Microsoft Graph permissions.',
      'Validate tenant scope and enable incremental synchronization.',
    ],
  },
  OKTA: {
    title: 'Okta workforce identity adapter',
    description: 'Evaluate administrators, groups, applications and lifecycle privileges.',
    category: 'Identity',
    requirements: ['Okta organization URL', 'OAuth service application', 'Read-only scopes'],
    evidence: [
      'Admins and groups',
      'Application assignments',
      'Lifecycle and policy administration',
    ],
    steps: [
      'Create an OAuth service application.',
      'Grant read-only management scopes.',
      'Validate organization access and enable system-log updates.',
    ],
  },
  GITLAB: {
    title: 'GitLab supply-chain adapter',
    description: 'Discover group, project, runner, environment and pipeline-control privileges.',
    category: 'Supply chain',
    requirements: ['GitLab URL', 'OAuth application or project token', 'Read API scope'],
    evidence: [
      'Group and project roles',
      'Protected branches and environments',
      'Runner and pipeline privileges',
    ],
    steps: [
      'Create a read-only integration identity.',
      'Select groups and projects in scope.',
      'Test API access and enable audit-event collection.',
    ],
  },
  JENKINS: {
    title: 'Jenkins supply-chain adapter',
    description: 'Map administrative, credential, job and deployment permissions.',
    category: 'Supply chain',
    requirements: ['Jenkins URL', 'Read-only service identity', 'Authorization strategy access'],
    evidence: [
      'Global and folder permissions',
      'Job and credential use',
      'Deployment control paths',
    ],
    steps: [
      'Create a dedicated read-only identity.',
      'Approve metadata access without credential-value access.',
      'Validate folders and enable scheduled synchronization.',
    ],
  },
  ARGOCD: {
    title: 'Argo CD deployment adapter',
    description: 'Correlate project RBAC, cluster destinations and production deployment control.',
    category: 'Supply chain',
    requirements: ['Argo CD URL', 'Read-only token', 'Project and application scope'],
    evidence: ['Projects and applications', 'RBAC policies', 'Cluster and namespace destinations'],
    steps: [
      'Create a read-only Argo CD role.',
      'Select approved projects.',
      'Validate application and destination discovery.',
    ],
  },
  VAULT: {
    title: 'HashiCorp Vault adapter',
    description: 'Identify policies and identities able to read, generate or administer secrets.',
    category: 'Secrets',
    requirements: [
      'Vault address',
      'Read-only AppRole or Kubernetes auth',
      'Namespace when applicable',
    ],
    evidence: [
      'Entities, groups and policies',
      'Auth-method administration',
      'Secret-engine control paths',
    ],
    steps: [
      'Create a metadata-only policy.',
      'Authenticate through AppRole or workload identity.',
      'Validate namespace scope without reading secret values.',
    ],
  },
  POSTGRESQL: {
    title: 'PostgreSQL entitlement adapter',
    description: 'Map database roles, memberships, ownership and export-capable privileges.',
    category: 'Data',
    requirements: ['Database endpoint', 'TLS configuration', 'Catalog-only read account'],
    evidence: [
      'Roles and memberships',
      'Schema and table privileges',
      'Ownership and replication rights',
    ],
    steps: [
      'Create a catalog-only monitoring user.',
      'Select databases and schemas.',
      'Validate metadata access and enable scheduled synchronization.',
    ],
  },
  SNOWFLAKE: {
    title: 'Snowflake entitlement adapter',
    description: 'Resolve users, roles, warehouses, sensitive objects and data-sharing privileges.',
    category: 'Data',
    requirements: ['Account identifier', 'Key-pair service user', 'Monitoring role'],
    evidence: [
      'Role hierarchy',
      'Database and warehouse grants',
      'Sharing and account administration',
    ],
    steps: [
      'Create a key-pair monitoring user.',
      'Grant approved metadata views.',
      'Validate account scope and schedule synchronization.',
    ],
  },
  'GOOGLE WORKSPACE': {
    title: 'Google Workspace identity adapter',
    description: 'Evaluate administrators, groups, applications and external-sharing controls.',
    category: 'SaaS',
    requirements: [
      'Workspace customer ID',
      'Domain-wide delegated service identity',
      'Read-only Admin SDK scopes',
    ],
    evidence: ['Admin roles and groups', 'Application access', 'External sharing administration'],
    steps: [
      'Create a dedicated delegated identity.',
      'Approve minimum read-only scopes.',
      'Validate domains and enable incremental updates.',
    ],
  },
  'MICROSOFT 365': {
    title: 'Microsoft 365 adapter',
    description: 'Correlate collaboration, messaging and tenant-administration privileges.',
    category: 'SaaS',
    requirements: ['Tenant ID', 'Application certificate', 'Approved Graph read scopes'],
    evidence: [
      'Administrative roles',
      'SharePoint and Teams control',
      'Exchange and data-export privileges',
    ],
    steps: [
      'Register a certificate-based application.',
      'Approve minimum read scopes.',
      'Select workloads and enable audit synchronization.',
    ],
  },
  SERVICENOW: {
    title: 'ServiceNow governance adapter',
    description:
      'Map elevated platform roles, approval authority and workflow-administration access.',
    category: 'SaaS',
    requirements: ['Instance URL', 'OAuth client', 'Read-only integration role'],
    evidence: [
      'Users, groups and roles',
      'Approval authority',
      'Workflow and integration administration',
    ],
    steps: [
      'Create an OAuth integration.',
      'Assign approved table-read roles.',
      'Validate scoped APIs and enable synchronization.',
    ],
  },
  SLACK: {
    title: 'Slack enterprise adapter',
    description: 'Discover organization administration, app management and export capabilities.',
    category: 'SaaS',
    requirements: [
      'Enterprise organization',
      'Admin-approved OAuth application',
      'Read-only scopes',
    ],
    evidence: [
      'Organization and workspace admins',
      'Application management',
      'Export and retention controls',
    ],
    steps: [
      'Create an admin-approved OAuth application.',
      'Grant minimum discovery scopes.',
      'Select workspaces and enable audit-log ingestion.',
    ],
  },
  CLOUDFLARE: {
    title: 'Cloudflare control-plane adapter',
    description: 'Evaluate account, DNS, access, edge and security-policy administration.',
    category: 'Cloud',
    requirements: ['Account ID', 'Scoped API token', 'Read-only account permissions'],
    evidence: [
      'Members and roles',
      'DNS and zone administration',
      'Access and security policy control',
    ],
    steps: [
      'Create a read-only scoped API token.',
      'Select accounts and zones.',
      'Validate permissions and enable audit-log synchronization.',
    ],
  },
};

const workspaceCopy: Record<
  WorkspaceView,
  { eyebrow: string; title: string; description: string; pathLabel: string }
> = {
  overview: {
    eyebrow: 'OVERVIEW',
    title: 'Privilege Intelligence Overview',
    description: 'Executive toxic-identity posture, category concentration, and live platform coverage.',
    pathLabel: 'Overview',
  },
  identities: {
    eyebrow: 'IDENTITIES',
    title: 'Identities · Effective Access',
    description: 'Investigate human and machine identities with evidence-backed privilege context.',
    pathLabel: 'Identities',
  },
  conflicts: {
    eyebrow: 'RULE FINDINGS',
    title: 'Rule Findings · Toxic Combinations',
    description: 'Review deterministic conflicts and the permissions that complete each pattern.',
    pathLabel: 'Rule findings',
  },
  'rule-builder': {
    eyebrow: 'RULE BUILDER',
    title: 'Rule Builder · Toxic Combinations',
    description:
      'Create, test, and publish organization-specific privilege rules without editing code.',
    pathLabel: 'Rule builder',
  },
  'attack-paths': {
    eyebrow: 'ATTACK PATHS',
    title: 'Attack Paths · Forward & Reverse Analysis',
    description:
      'Trace privilege pivots to high-value resources, or reverse the path to locate the attack source.',
    pathLabel: 'Attack paths',
  },
  coverage: {
    eyebrow: 'CONNECTED PLATFORMS',
    title: 'Connected Platforms · Evidence Coverage',
    description: 'Configure adapters and review where PID evaluates privilege combinations.',
    pathLabel: 'Connected Platforms',
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
  const [copilotHistory, setCopilotHistory] = useState<Array<{ question: string; answer: string }>>(
    [],
  );
  const [pathDirection, setPathDirection] = useState<AttackPathDirection>('forward');
  const [attackPathDrawerOpen, setAttackPathDrawerOpen] = useState(false);
  const [simulation, setSimulation] = useState<ToxicAccessSimulation | null>(null);
  const [coverage, setCoverage] = useState<RealtimeCoverageSummary | null>(null);
  const [simulationMode, setSimulationMode] = useState<'permission' | 'assignment'>('permission');
  const [simulating, setSimulating] = useState(false);
  const [activeView, setActiveView] = useState<WorkspaceView>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [ruleFilter, setRuleFilter] = useState<string | null>(null);
  const [identityTypeFilter, setIdentityTypeFilter] = useState<IdentityTypeFilter>('all');
  const [connectorPlatform, setConnectorPlatform] = useState<string | null>(null);
  const [connectorOnboardingStarted, setConnectorOnboardingStarted] = useState(false);
  const [connectorValidationRequested, setConnectorValidationRequested] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [trendRange, setTrendRange] = useState(30);
  const [postureTrend, setPostureTrend] = useState<ExecutivePostureTrend | null>(null);
  const [immunityWindows, setImmunityWindows] = useState<ImmunityWindow[]>([]);
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
      const [summaryResponse, accessResponse, coverageResponse] = await Promise.all([
        fetch(`${apiUrl}/risk/summary`),
        fetch(`${apiUrl}/toxic-access/identities`),
        fetch(`${apiUrl}/toxic-access/coverage/realtime`),
      ]);
      if (!summaryResponse.ok) throw new Error(`Identity API returned ${summaryResponse.status}`);
      if (!accessResponse.ok) throw new Error(`Toxic Access API returned ${accessResponse.status}`);
      if (!coverageResponse.ok) throw new Error(`Coverage API returned ${coverageResponse.status}`);
      const next = (await summaryResponse.json()) as RiskSummary;
      const evaluations = (await accessResponse.json()) as ToxicAccessEvaluation[];
      const liveCoverage = (await coverageResponse.json()) as RealtimeCoverageSummary;
      setSummary(next);
      setAccessEvaluations(evaluations);
      setCoverage(liveCoverage);
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

  const loadTrend = useCallback(
    async (days = trendRange) => {
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
    },
    [trendRange],
  );

  const loadImmunityWindows = useCallback(async () => {
    try {
      const responses = await Promise.all(
        [7, 15, 30].map((days) =>
          fetch(`${apiUrl}/risk/executive-trend?days=${days}`, { cache: 'no-store' }),
        ),
      );
      const windows = await Promise.all(
        responses.map(async (response, index) => {
          if (!response.ok) {
            return {
              days: [7, 15, 30][index],
              toxicIdentityChangePercent: 0,
              immunityGainPercent: 0,
            } satisfies ImmunityWindow;
          }
          return toImmunityWindow((await response.json()) as ExecutivePostureTrend);
        }),
      );
      setImmunityWindows(windows);
    } catch {
      setImmunityWindows([]);
    }
  }, []);

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
        loadImmunityWindows(),
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
  }, [loadImmunityWindows, trendRange]);

  useEffect(() => {
    void loadSummary();
    const interval = window.setInterval(() => void loadSummary(true), 15_000);
    return () => window.clearInterval(interval);
  }, [loadSummary]);

  useEffect(() => {
    setConnectorOnboardingStarted(false);
    setConnectorValidationRequested(false);
  }, [connectorPlatform]);

  useEffect(() => {
    const closeOverlays = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      if (connectorPlatform) {
        setConnectorPlatform(null);
        return;
      }
      if (copilotOpen) setCopilotOpen(false);
    };
    window.addEventListener('keydown', closeOverlays);
    return () => window.removeEventListener('keydown', closeOverlays);
  }, [connectorPlatform, copilotOpen]);

  useEffect(() => {
    document.title = `${workspaceCopy[activeView].title} · UnoSecur PID`;
  }, [activeView]);

  useEffect(() => {
    if (!attackPathDrawerOpen) return;
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setAttackPathDrawerOpen(false);
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [attackPathDrawerOpen]);

  useEffect(() => {
    void loadTrend();
  }, [loadTrend]);

  useEffect(() => {
    void loadImmunityWindows();
  }, [loadImmunityWindows]);

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

  const displayIdentities = useMemo<ToxicIdentity[]>(() => {
    const seededById = new Map(summary?.topIdentities.map((identity) => [identity.id, identity]));
    const connected = accessEvaluations.map((evaluation) => {
      const seeded = seededById.get(evaluation.identityId);
      if (seeded) return seeded;
      const permissions = evaluation.conflicts.flatMap(({ evidence }) =>
        evidence.map(({ permission }) => permission),
      );
      const path = evaluation.conflicts[0]?.evidence[0]?.accessPath ?? [];
      return {
        id: evaluation.identityId,
        name: evaluation.displayName,
        type: evaluation.identityType,
        department: evaluation.provider,
        riskScore: Math.min(100, evaluation.summary.critical * 25 + evaluation.summary.total * 10),
        confidence: evaluation.conflicts.length > 0 ? 95 : 80,
        platforms: evaluation.summary.affectedPlatforms.length
          ? evaluation.summary.affectedPlatforms
          : [evaluation.provider],
        factors: [],
        attackPath: path,
        blastRadius: {
          accounts: new Set(evaluation.summary.affectedPlatforms).size,
          clusters: evaluation.provider === 'KUBERNETES' ? 1 : 0,
          secrets: permissions.filter((permission) => /secret|key|token/i.test(permission)).length,
          databases: permissions.filter((permission) => /database|sql|rds/i.test(permission))
            .length,
        },
      };
    });
    if (coverage?.evidenceMode === 'CONNECTED') return connected;
    const connectedIds = new Set(connected.map(({ id }) => id));
    return [
      ...connected,
      ...(summary?.topIdentities.filter(({ id }) => !connectedIds.has(id)) ?? []),
    ];
  }, [accessEvaluations, coverage?.evidenceMode, summary]);

  const selectedIdentity = useMemo(
    () => displayIdentities.find(({ id }) => id === selectedId) ?? displayIdentities[0] ?? null,
    [displayIdentities, selectedId],
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
  const removableAssignments = useMemo(
    () =>
      [
        ...new Set(
          selectedAccess?.conflicts.flatMap(({ evidence }) =>
            evidence.map(({ accessPath }) => accessPath[1]).filter(Boolean),
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

  const runSimulation = async (value: string, mode: 'permission' | 'assignment') => {
    if (!selectedIdentity) return;
    setSimulating(true);
    try {
      const response = await fetch(
        `${apiUrl}/toxic-access/identities/${selectedIdentity.id}/simulate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(
            mode === 'permission' ? { removePermissions: [value] } : { removeAssignments: [value] },
          ),
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
      const next = (await response.json()) as CopilotAnswer;
      setAnswer(next);
      setCopilotHistory((history) => [{ question: prompt, answer: next.answer }, ...history].slice(0, 6));
    } catch (reason) {
      const fallback = {
        answer: reason instanceof Error ? reason.message : 'Copilot is unavailable.',
        source: 'deterministic-fallback' as const,
        model: 'local',
      };
      setAnswer(fallback);
      setCopilotHistory((history) =>
        [{ question: prompt, answer: fallback.answer }, ...history].slice(0, 6),
      );
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
          label: 'Affected platforms',
          value: affectedPlatforms,
          Icon: GitBranch,
          tone: 'accent',
          target: 'coverage' as WorkspaceView,
        },
        {
          label: 'Identities evaluated',
          value: coverage?.identitiesObserved ?? displayIdentities.length,
          Icon: Activity,
          tone: 'neutral',
          target: 'identities' as WorkspaceView,
        },
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
  const coveragePlatforms = (() => {
    const withConflicts = platformConflictCounts.filter(
      (item) => item.platform !== 'JENKINS',
    );
    const jenkins = platformConflictCounts.find((item) => item.platform === 'JENKINS') ?? {
      platform: 'JENKINS',
      identities: 0,
    };
    return [
      ...withConflicts.slice(0, 6),
      { ...jenkins, conflicts: 0 },
    ];
  })();
  const flowConnectorLines = coveragePlatforms
    .map((item, index) => ({ ...item, index }))
    .filter((item) => item.conflicts > 0)
    .map((item) => ({
      platform: item.platform,
      sourceY: ((item.index + 0.5) / coveragePlatforms.length) * 160,
    }));
  const connectorCoverageItems = Object.keys(connectorGuides).map((platform, index) => {
    const live = coverage?.connectors.find(
      (connector) => connector.platform.toUpperCase() === platform,
    );
    const observed = platformConflictCounts.find((item) => item.platform === platform);
    return (
      live ?? {
        id: `catalog-${index}`,
        platform,
        status: 'READY_TO_CONNECT' as const,
        identities: observed?.identities ?? 0,
        entitlements: 0,
        conflicts: observed?.conflicts ?? 0,
        criticalConflicts: 0,
        syncMode: 'API_SYNC' as const,
        dataSource: `${connectorGuides[platform].category} onboarding adapter`,
        evaluatedAt: new Date().toISOString(),
        domain: connectorGuides[platform].category.toUpperCase().replace(' ', '_'),
      }
    );
  });
  const selectedConnector = connectorPlatform
    ? (connectorGuides[connectorPlatform.toUpperCase()] ?? {
        title: `${connectorPlatform} adapter`,
        description: `Connect ${connectorPlatform} effective permission evidence to PID.`,
        category: 'SaaS' as const,
        requirements: ['Read-only discovery credentials', 'Target tenant or account scope'],
        evidence: ['Identities and roles', 'Effective permissions', 'Target resources'],
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
          'Write a custom query for AWS admin + audit disable',
        ]
      : activeView === 'attack-paths'
        ? [
            'Explain this attack path forward',
            'Reverse this path and find the likely source',
            'Which privilege is the highest-risk pivot?',
            'What resource is the blast-radius tip?',
            'Simulate removing the first privilege hop',
            'Custom query: list all paths that reach Vault secrets',
            'How do I reduce this path without breaking business access?',
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
            'Custom query: top critical identities by platform',
            'How do I create my own toxic combination?',
            'Summarize rule category concentration',
            'Which connected platforms have the most conflicts?',
          ];

  return (
    <div className="app-shell">
      <header className="app-topbar">
        <div className="topbar-brand">
          <img
            src="/unosecur-logo.png?v=3"
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
              <p className="page-path">
                Privilege Intelligence &amp; Detection / {viewCopy.pathLabel}
              </p>
              <h1>{viewCopy.title}</h1>
              <span>{viewCopy.description}</span>
            </div>
            {activeView !== 'overview' && (
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
                    {searchResults.length === 0 && (
                      <p>No matching identity, rule or permission.</p>
                    )}
                  </div>
                )}
              </div>
            )}
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
                    <div className="pid-flow-connectors" aria-hidden>
                      <svg viewBox="0 0 220 160" preserveAspectRatio="none">
                        <defs>
                          <linearGradient id="pidFlowStroke" x1="0" y1="0" x2="1" y2="0">
                            <stop offset="0%" stopColor="#2f61ed" stopOpacity="0" />
                            <stop offset="45%" stopColor="#2f61ed" stopOpacity="0.55" />
                            <stop offset="100%" stopColor="#80d568" stopOpacity="0.85" />
                          </linearGradient>
                          <marker
                            id="pidFlowArrow"
                            markerWidth="7"
                            markerHeight="7"
                            refX="5"
                            refY="3"
                            orient="auto"
                          >
                            <path d="M0,0 L6,3 L0,6 Z" fill="#5a8f4f" />
                          </marker>
                        </defs>
                        {flowConnectorLines.map((line, index) => (
                          <path
                            key={line.platform}
                            className="pid-flow-line"
                            style={{ animationDelay: `${index * 0.3}s` }}
                            d={`M4,${line.sourceY} C90,${line.sourceY} 130,80 214,80`}
                            markerEnd="url(#pidFlowArrow)"
                          />
                        ))}
                      </svg>
                    </div>
                    <div className="pid-integrations">
                      <div className="pid-section-heading">
                        <h3>Platform coverage</h3>
                      </div>
                      <div className="pid-integration-list">
                        {coveragePlatforms.map(({ platform, conflicts, identities }) => {
                            const maxConflicts = Math.max(
                              ...coveragePlatforms.map((item) => item.conflicts),
                              1,
                            );
                            return (
                              <button
                                key={platform}
                                className={`pid-integration-card ${conflicts > 0 ? 'has-risk' : ''}`}
                                onClick={() => {
                                  setConnectorPlatform(platform);
                                }}
                              >
                                <PlatformIcon platform={platform} />
                                <span className="pid-platform-copy">
                                  <strong>{platform}</strong>
                                  <small>
                                    {conflicts > 0
                                      ? `${conflicts} conflicts · ${identities} identities`
                                      : 'Connected · no conflicts'}
                                  </small>
                                  <span className="pid-platform-bar" aria-hidden>
                                    <i
                                      style={{
                                        width: `${Math.max((conflicts / maxConflicts) * 100, 6)}%`,
                                      }}
                                    />
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
                          <b>{coverage?.identitiesObserved ?? displayIdentities.length}</b>
                          <span>Identities</span>
                        </button>
                      </div>
                    </div>
                  </section>

                  {coverage && (
                    <section className="live-intelligence-strip">
                      <div className="live-intelligence-title">
                        <span>
                          <Radio size={16} /> LIVE PRIVILEGE SIGNAL
                        </span>
                        <strong>
                          {coverage.connectedPlatforms} of {coverage.availablePlatforms} control
                          planes reporting
                        </strong>
                        <small>
                          {coverage.identitiesObserved} identities · {coverage.entitlementsObserved}{' '}
                          effective entitlements · evaluated every {coverage.refreshIntervalSeconds}
                          s
                          {lastUpdated ? ` · refreshed ${lastUpdated.toLocaleTimeString()}` : ''}
                        </small>
                        <small className="evidence-mode">
                          {coverage.evidenceMode === 'CONNECTED'
                            ? `Connected evidence · ${coverage.evidenceSource}`
                            : 'Seeded evaluation evidence · connect an approved adapter to enable live synchronization'}
                        </small>
                      </div>
                      <div className="live-connector-pills">
                        {coverage.connectors.slice(0, 7).map((connector) => (
                          <button
                            className={connector.status === 'CONNECTED' ? 'connected' : 'ready'}
                            key={connector.id}
                            onClick={() => {
                              setConnectorPlatform(connector.platform);
                            }}
                          >
                            <i />
                            <PlatformIcon platform={connector.platform} compact />
                            {connector.platform}
                            <small>{connector.entitlements || 'Configure'}</small>
                          </button>
                        ))}
                        <button
                          type="button"
                          className={`live-refresh-pill ${refreshing ? 'refreshing' : ''}`}
                          aria-busy={refreshing}
                          disabled={refreshing}
                          onClick={() => void refreshLiveData()}
                        >
                          <RefreshCw size={14} aria-hidden />
                          {refreshing ? 'Refreshing…' : 'Refresh'}
                        </button>
                      </div>
                    </section>
                  )}
                  <ExecutiveTrendChart
                    loading={trendLoading}
                    immunityWindows={immunityWindows}
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
                        {ruleCategories.length === 0 && (
                          <div className="empty-conflicts">
                            No toxic categories detected yet. Connect evidence or refresh evaluation.
                          </div>
                        )}
                      </div>
                    </article>
                  </div>

                </>
              )}

              {activeView === 'identities' && (
                <article className="panel overview-hotspots identities-hotspots">
                  <div className="panel-title">
                    <div>
                      <p>PRIORITY HOTSPOTS</p>
                      <h2>Identities needing attention first</h2>
                    </div>
                  </div>
                  <div className="hotspot-grid">
                    {displayIdentities.slice(0, 4).map((identity) => {
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
                  {displayIdentities
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

                  {activeView === 'identities' && (
                    <button
                      type="button"
                      className="attack-path-trigger"
                      onClick={() => setAttackPathDrawerOpen(true)}
                    >
                      <Workflow size={16} /> View attack path
                    </button>
                  )}

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
                          // Prefer the path start so the blue flow paints identity → resource.
                          const path = conflict.evidence[0]?.accessPath.filter(Boolean) ?? [];
                          setSelectedNode(path[0] ?? path.at(-1) ?? null);
                          if (activeView === 'identities') {
                            setAttackPathDrawerOpen(true);
                          } else {
                            selectWorkspaceView('attack-paths');
                          }
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
                      <h2>
                        {pathDirection === 'reverse'
                          ? 'Reverse path · find the attack source'
                          : 'Identity → high-value resource'}
                      </h2>
                    </div>
                    <div className="path-direction-toggle" aria-label="Attack path direction">
                      <button
                        type="button"
                        className={pathDirection === 'forward' ? 'active' : ''}
                        onClick={() => setPathDirection('forward')}
                      >
                        Forward
                      </button>
                      <button
                        type="button"
                        className={pathDirection === 'reverse' ? 'active' : ''}
                        onClick={() => setPathDirection('reverse')}
                      >
                        Reverse source
                      </button>
                    </div>
                  </div>
                  {/* Mount only when visible — React Flow breaks if initialized under display:none. */}
                  {activeView === 'attack-paths' ? (
                    <AttackPathGraph
                      key={`${pathDirection}-${selectedIdentity?.id ?? 'none'}`}
                      direction={pathDirection}
                      paths={attackPathGraphPaths}
                      selectedNode={selectedNode}
                      onSelectNode={setSelectedNode}
                    />
                  ) : (
                    <div className="attack-graph-canvas attack-graph-canvas-placeholder" />
                  )}
                  <div className="path-insight">
                    <Zap size={17} />
                    <span>
                      {pathDirection === 'reverse'
                        ? `Working backward from ${
                            selectedAccessPath.at(-1) ?? selectedNode ?? 'the compromised asset'
                          } to locate the originating identity and privilege hops.`
                        : `${selectedNode ?? selectedAccessPath[0] ?? 'Selected node'} is part of an effective-access path contributing to ${
                            selectedAccess?.conflicts[0]?.title ?? 'this investigation'
                          }.`}
                    </span>
                  </div>
                </article>

                <article className="panel simulator">
                  <div className="panel-title">
                    <div>
                      <p>WHAT-IF REMEDIATION</p>
                      <h2>
                        Simulate least privilege for{' '}
                        {identityTypeLabel(selectedAccess?.identityType)}
                      </h2>
                    </div>
                    <Sparkles size={19} />
                  </div>
                  <p className="muted">
                    Remove a permission or its originating role to compare risk reduction, disrupted
                    attack paths, protected resources, and retained business access. No live access
                    is changed.
                  </p>
                  <div className="simulation-mode">
                    <button
                      className={simulationMode === 'permission' ? 'active' : ''}
                      onClick={() => {
                        setSimulationMode('permission');
                        setSimulation(null);
                      }}
                    >
                      Permission
                    </button>
                    <button
                      className={simulationMode === 'assignment' ? 'active' : ''}
                      onClick={() => {
                        setSimulationMode('assignment');
                        setSimulation(null);
                      }}
                    >
                      Role / assignment
                    </button>
                  </div>
                  <div className="permission-list">
                    {(simulationMode === 'permission'
                      ? removablePermissions
                      : removableAssignments
                    ).map((item) => (
                      <button
                        disabled={simulating}
                        key={item}
                        onClick={() => void runSimulation(item, simulationMode)}
                      >
                        {item}
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
                        <span>Risk reduction</span>
                        <strong className="positive">{simulation.riskReductionPercent}%</strong>
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
                          Revoke{' '}
                          <b>
                            {[
                              ...simulation.removedPermissions,
                              ...simulation.removedAssignments,
                            ].join(', ')}
                          </b>{' '}
                          {simulation.resolvedConflicts.length > 0
                            ? `to resolve ${simulation.resolvedConflicts.length} verified toxic combination${
                                simulation.resolvedConflicts.length === 1 ? '' : 's'
                              } while retaining ${simulation.businessAccessPreservedPercent}% of existing business access.`
                            : 'does not fully resolve a toxic combination. Evaluate another matched privilege before submitting a change.'}
                        </span>
                        <small>
                          Control recommendation: {selectedAccess?.conflicts[0]?.remediation}
                        </small>
                      </section>
                      <section className="security-improvement">
                        <strong>Projected security improvement</strong>
                        <div className="outcome-grid">
                          {simulation.securityOutcomes.map((outcome) => (
                            <span key={outcome}>
                              <ShieldCheck size={14} /> {outcome}
                            </span>
                          ))}
                        </div>
                        <small>
                          Residual exposure: <b>{simulation.residualSeverity}</b>
                          {simulation.protectedResources.length > 0 &&
                            ` · Protected scopes: ${simulation.protectedResources.slice(0, 3).join(', ')}`}
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
                  <span>
                    {coverage?.connectedPlatforms ?? platformConflictCounts.length} connected
                    platforms
                  </span>
                </div>
                <div className="coverage-grid">
                  {connectorCoverageItems.map(
                    ({
                      id,
                      platform,
                      conflicts,
                      identities,
                      entitlements,
                      criticalConflicts,
                      status,
                      syncMode,
                      dataSource,
                    }) => (
                      <button
                        className={`coverage-item ${status === 'CONNECTED' ? 'connected' : 'ready'}`}
                        key={id}
                        onClick={() => {
                          setConnectorOnboardingStarted(false);
                          setConnectorPlatform(platform);
                        }}
                      >
                        <div className="coverage-card-heading">
                          <PlatformIcon platform={platform} />
                          <div className="coverage-card-actions">
                            <span className="connector-status">
                              <i /> {status.replaceAll('_', ' ')}
                            </span>
                            <Settings size={15} className="coverage-settings" />
                          </div>
                        </div>
                        <strong>{platform}</strong>
                        <small>{dataSource}</small>
                        <span>
                          {conflicts > 0 ? `${conflicts} matched conflicts` : 'Ready to configure'}
                        </span>
                        <small>
                          {identities > 0
                            ? `${identities} identities · ${entitlements} entitlements`
                            : 'View configuration requirements'}
                        </small>
                        <small>
                          {criticalConflicts} critical · {syncMode.replaceAll('_', ' ')}
                        </small>
                      </button>
                    ),
                  )}
                </div>
                {coverage && (
                  <div className="entitlement-stream">
                    <div className="panel-title">
                      <div>
                        <p>LIVE ENTITLEMENT ACTIVITY</p>
                        <h2>Changes entering privilege evaluation</h2>
                      </div>
                      <span className="live-indicator">
                        <i /> Evaluated {new Date(coverage.evaluatedAt).toLocaleTimeString()}
                      </span>
                    </div>
                    {coverage.recentEntitlementEvents.slice(0, 8).map((event) => (
                      <button
                        key={event.id}
                        onClick={() => {
                          setSelectedId(event.identityId);
                          selectWorkspaceView(event.createsConflict ? 'conflicts' : 'identities');
                        }}
                      >
                        <span className={event.createsConflict ? 'event-risk' : 'event-safe'}>
                          <i />
                        </span>
                        <span>
                          <strong>{event.displayName}</strong>
                          <small>
                            {event.platform} · {identityTypeLabel(event.identityType)}
                          </small>
                        </span>
                        <span>
                          <strong>{event.permission}</strong>
                          <small>via {event.assignment}</small>
                        </span>
                        <span>
                          <small>{event.resource}</small>
                        </span>
                        <b>{event.createsConflict ? 'CONFLICT SIGNAL' : 'OBSERVED'}</b>
                      </button>
                    ))}
                  </div>
                )}
              </article>
            </>
          )}
        </section>
      </div>

      {selectedConnector && (
        <button
          aria-label="Close connector details"
          className="connector-backdrop"
          onClick={() => setConnectorPlatform(null)}
          type="button"
        />
      )}

      {copilotOpen && (
        <button
          aria-label="Close Copilot"
          className="copilot-backdrop"
          onClick={() => setCopilotOpen(false)}
          type="button"
        />
      )}

      {attackPathDrawerOpen && (
        <button
          aria-label="Close attack path"
          className="attack-path-backdrop"
          onClick={() => setAttackPathDrawerOpen(false)}
          type="button"
        />
      )}

      <section
        aria-hidden={!attackPathDrawerOpen}
        aria-label="Interactive attack path"
        className={`attack-path-drawer ${attackPathDrawerOpen ? 'open' : ''}`}
      >
        {attackPathDrawerOpen && (
          <>
            <div className="attack-path-drawer-header">
              <div>
                <p>INTERACTIVE ATTACK PATH</p>
                <h2>
                  {pathDirection === 'reverse'
                    ? 'Reverse path · find the attack source'
                    : `${selectedIdentity?.name ?? 'Identity'} → high-value resource`}
                </h2>
              </div>
              <div className="attack-path-drawer-actions">
                <div className="path-direction-toggle" aria-label="Attack path direction">
                  <button
                    type="button"
                    className={pathDirection === 'forward' ? 'active' : ''}
                    onClick={() => setPathDirection('forward')}
                  >
                    Forward
                  </button>
                  <button
                    type="button"
                    className={pathDirection === 'reverse' ? 'active' : ''}
                    onClick={() => setPathDirection('reverse')}
                  >
                    Reverse source
                  </button>
                </div>
                <button
                  type="button"
                  aria-label="Close attack path"
                  className="attack-path-drawer-close"
                  onClick={() => setAttackPathDrawerOpen(false)}
                >
                  <X size={18} />
                </button>
              </div>
            </div>
            <AttackPathGraph
              key={`drawer-${pathDirection}-${selectedIdentity?.id ?? 'none'}`}
              direction={pathDirection}
              paths={attackPathGraphPaths}
              selectedNode={selectedNode}
              onSelectNode={setSelectedNode}
            />
            <div className="path-insight">
              <Zap size={17} />
              <span>
                {pathDirection === 'reverse'
                  ? `Working backward from ${
                      selectedAccessPath.at(-1) ?? selectedNode ?? 'the compromised asset'
                    } to locate the originating identity and privilege hops.`
                  : `${selectedNode ?? selectedAccessPath[0] ?? 'Selected node'} is part of an effective-access path contributing to ${
                      selectedAccess?.conflicts[0]?.title ?? 'this investigation'
                    }.`}
              </span>
            </div>
          </>
        )}
      </section>

      <section
        aria-hidden={!selectedConnector}
        aria-label="Connector configuration requirements"
        className={`connector-drawer ${selectedConnector ? 'open' : ''}`}
      >
        {selectedConnector && (
          <>
            <div className="connector-header">
              <div>
                <p>ADAPTER CONFIGURATION</p>
                <h2>{selectedConnector.title}</h2>
              </div>
              <button
                aria-label="Close connector details"
                onClick={() => setConnectorPlatform(null)}
              >
                <X size={18} />
              </button>
            </div>
            <p>{selectedConnector.description}</p>
            <span className="connector-category">{selectedConnector.category}</span>
            <h3>Required details</h3>
            <ul>
              {selectedConnector.requirements.map((requirement) => (
                <li key={requirement}>
                  <Check size={15} /> {requirement}
                </li>
              ))}
            </ul>
            <h3>Evidence collected</h3>
            <ul>
              {selectedConnector.evidence.map((item) => (
                <li key={item}>
                  <ShieldCheck size={15} /> {item}
                </li>
              ))}
            </ul>
            <h3>Configuration flow</h3>
            <ol>
              {selectedConnector.steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
            <button
              className="connector-action"
              onClick={() => setConnectorOnboardingStarted(true)}
            >
              {connectorOnboardingStarted ? <Check size={16} /> : <Settings size={16} />}
              {connectorOnboardingStarted ? 'Connection form opened' : 'Configure connection'}
            </button>
            {connectorOnboardingStarted && (
              <form
                className="connector-configuration-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  setConnectorValidationRequested(true);
                }}
              >
                <div className="connector-form-heading">
                  <strong>Secure connection details</strong>
                  <span>Required values are masked and prepared for vault-backed validation.</span>
                </div>
                {selectedConnector.requirements.map((requirement) => {
                  const secretField = /secret|password|private key|token|certificate|json/i.test(
                    requirement,
                  );
                  return (
                    <label key={`field-${requirement}`}>
                      <span>{requirement}</span>
                      {/json|certificate/i.test(requirement) ? (
                        <textarea
                          aria-label={requirement}
                          placeholder={`Enter ${requirement.toLowerCase()}`}
                          required
                          rows={3}
                        />
                      ) : (
                        <input
                          aria-label={requirement}
                          autoComplete="off"
                          placeholder={`Enter ${requirement.toLowerCase()}`}
                          required
                          type={secretField ? 'password' : 'text'}
                        />
                      )}
                    </label>
                  );
                })}
                <button className="connector-validate" type="submit">
                  <ShieldCheck size={15} /> Validate read-only connection
                </button>
              </form>
            )}
            {connectorValidationRequested && (
              <div className="connector-onboarding-notice">
                <strong>Connection request prepared</strong>
                <span>
                  The adapter must send these values to the organization vault before the live
                  validation job can run. Browser-only storage is intentionally disabled.
                </span>
              </div>
            )}
            <small>
              Credentials are stored only in the organization-approved secrets vault. PID validates
              least-privilege, read-only access before enabling encrypted live synchronization.
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
              ? 'Ask how to design, test, scope, and publish your own toxic-combination rule — or enter a custom query.'
              : activeView === 'attack-paths'
                ? 'Ask for forward impact analysis, reverse source tracing, or a custom path query.'
                : `Ask about ${selectedIdentity?.name ?? 'a toxic identity'}, attack paths, remediation, or enter any custom evidence query.`}
          </div>
          <p className="copilot-query-hint">
            Custom queries supported — try “top critical identities by platform”, “reverse path to
            Vault”, or “simulate removing iam:PassRole”.
          </p>
          {copilotHistory.length > 0 && (
            <div className="copilot-history" aria-label="Recent Copilot answers">
              {copilotHistory.slice(0, 3).map((item) => (
                <button
                  key={`${item.question}-${item.answer.slice(0, 24)}`}
                  className="copilot-history-item"
                  type="button"
                  onClick={() => void askCopilot(undefined, item.question)}
                >
                  <strong>{item.question}</strong>
                  <span>{item.answer.slice(0, 140)}{item.answer.length > 140 ? '…' : ''}</span>
                </button>
              ))}
            </div>
          )}
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
            placeholder="Ask a question or type a custom query…"
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
