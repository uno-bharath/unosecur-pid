'use client';

import {
  CheckCircle2,
  FlaskConical,
  Plus,
  Rocket,
  Save,
  ShieldCheck,
  Trash2,
  X,
} from 'lucide-react';
import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';

type Category =
  | 'SEGREGATION_OF_DUTIES'
  | 'CROSS_PLATFORM_CONTROL'
  | 'SUPPLY_CHAIN_PIVOT'
  | 'DATA_CONTROL_CONFLICT';
type Severity = 'critical' | 'high' | 'medium' | 'low';
type IdentityType = 'HUMAN' | 'SERVICE_ACCOUNT' | 'WORKLOAD';

interface RequirementDraft {
  id: string;
  platform: string;
  permissions: string;
  resourcePattern: string;
}

interface RuleDraft {
  title: string;
  description: string;
  category: Category;
  severity: Severity;
  businessImpact: string;
  remediation: string;
  requirements: RequirementDraft[];
  identityTypes: IdentityType[];
  minimumPlatforms: string;
  mitreMappings: string;
  nistMappings: string;
}

interface RuleRecord {
  id: string;
  status: 'DRAFT' | 'PUBLISHED';
  version: number;
  createdBy: string;
  updatedAt: string;
  rule: {
    id: string;
    title: string;
    category: Category;
    severity: Severity;
    requirements: Array<{
      id: string;
      platform?: string;
      anyPermissions: string[];
      resourcePattern?: string;
    }>;
    identityTypes?: IdentityType[];
  };
}

interface RulePreview {
  affectedIdentityCount: number;
  matchedGrantCount: number;
  affectedIdentities: Array<{
    identityId: string;
    displayName: string;
    identityType: string;
    matchedPermissions: string[];
  }>;
}

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000/api';
const blankRequirement = (index: number): RequirementDraft => ({
  id: `condition-${index}`,
  platform: '',
  permissions: '',
  resourcePattern: '',
});
const initialDraft = (): RuleDraft => ({
  title: '',
  description: '',
  category: 'SEGREGATION_OF_DUTIES',
  severity: 'high',
  businessImpact: '',
  remediation: '',
  requirements: [blankRequirement(1), blankRequirement(2)],
  identityTypes: ['HUMAN', 'SERVICE_ACCOUNT', 'WORKLOAD'],
  minimumPlatforms: '',
  mitreMappings: '',
  nistMappings: 'AC-5 Separation of Duties, AC-6 Least Privilege',
});

function splitValues(value: string): string[] {
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

export function VisualRuleBuilder({ onRulesChanged }: { onRulesChanged: () => void }) {
  const [draft, setDraft] = useState<RuleDraft>(initialDraft);
  const [rules, setRules] = useState<RuleRecord[]>([]);
  const [preview, setPreview] = useState<RulePreview | null>(null);
  const [busy, setBusy] = useState<'preview' | 'save' | 'publish' | 'delete' | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadRules = useCallback(async () => {
    const response = await fetch(`${apiUrl}/toxic-access/rules/custom`);
    if (!response.ok) throw new Error(`Custom rule API returned ${response.status}`);
    setRules((await response.json()) as RuleRecord[]);
  }, []);

  useEffect(() => {
    void loadRules().catch((reason: unknown) =>
      setError(reason instanceof Error ? reason.message : 'Custom rules could not be loaded.'),
    );
  }, [loadRules]);

  const payload = useMemo(
    () => ({
      title: draft.title,
      description: draft.description,
      category: draft.category,
      severity: draft.severity,
      businessImpact: draft.businessImpact,
      remediation: draft.remediation,
      requirements: draft.requirements.map((requirement, index) => ({
        id: requirement.id || `condition-${index + 1}`,
        ...(requirement.platform.trim() ? { platform: requirement.platform.trim() } : {}),
        anyPermissions: splitValues(requirement.permissions),
        ...(requirement.resourcePattern.trim()
          ? { resourcePattern: requirement.resourcePattern.trim() }
          : {}),
      })),
      identityTypes: draft.identityTypes,
      ...(draft.minimumPlatforms ? { minimumPlatforms: Number(draft.minimumPlatforms) } : {}),
      mitreMappings: splitValues(draft.mitreMappings),
      nistMappings: splitValues(draft.nistMappings),
    }),
    [draft],
  );

  const validate = (): string | null => {
    if (payload.title.trim().length < 5) return 'Give the rule a descriptive title.';
    if (payload.description.trim().length < 10) return 'Describe the dangerous capability.';
    if (payload.businessImpact.trim().length < 10) return 'Explain the business impact.';
    if (payload.remediation.trim().length < 10) return 'Provide a practical remediation.';
    if (payload.identityTypes.length === 0) return 'Select at least one identity type.';
    if (payload.requirements.some(({ anyPermissions }) => anyPermissions.length === 0)) {
      return 'Every condition needs at least one permission.';
    }
    if (payload.nistMappings.length === 0) return 'Add at least one control mapping.';
    return null;
  };

  const request = async (
    action: 'preview' | 'save',
    endpoint: string,
  ): Promise<RulePreview | RuleRecord> => {
    const validation = validate();
    if (validation) throw new Error(validation);
    const response = await fetch(`${apiUrl}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const detail = (await response.json().catch(() => null)) as {
        message?: string[] | string;
      } | null;
      throw new Error(
        Array.isArray(detail?.message)
          ? detail.message.join(' ')
          : (detail?.message ?? `Rule ${action} failed with status ${response.status}.`),
      );
    }
    return response.json() as Promise<RulePreview | RuleRecord>;
  };

  const previewRule = async () => {
    setBusy('preview');
    setError(null);
    setMessage(null);
    try {
      setPreview((await request('preview', '/toxic-access/rules/custom/preview')) as RulePreview);
      setMessage('Preview completed against the current effective-access evidence.');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Rule preview failed.');
    } finally {
      setBusy(null);
    }
  };

  const saveRule = async (event: FormEvent) => {
    event.preventDefault();
    setBusy('save');
    setError(null);
    setMessage(null);
    try {
      await request('save', '/toxic-access/rules/custom');
      await loadRules();
      setDraft(initialDraft());
      setPreview(null);
      setMessage('Rule saved as a governed draft. Test and publish it when ready.');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Rule could not be saved.');
    } finally {
      setBusy(null);
    }
  };

  const publishRule = async (id: string) => {
    setBusy('publish');
    setError(null);
    try {
      const response = await fetch(`${apiUrl}/toxic-access/rules/custom/${id}/publish`, {
        method: 'POST',
      });
      if (!response.ok) throw new Error(`Rule publication failed with status ${response.status}.`);
      await loadRules();
      onRulesChanged();
      setMessage('Rule published. It is now included in continuous identity evaluation.');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Rule publication failed.');
    } finally {
      setBusy(null);
    }
  };

  const deleteRule = async (id: string) => {
    setBusy('delete');
    setError(null);
    try {
      const response = await fetch(`${apiUrl}/toxic-access/rules/custom/${id}`, {
        method: 'DELETE',
      });
      if (!response.ok) throw new Error(`Draft deletion failed with status ${response.status}.`);
      await loadRules();
      setMessage('Draft deleted.');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Draft deletion failed.');
    } finally {
      setBusy(null);
    }
  };

  const updateRequirement = (index: number, field: keyof RequirementDraft, value: string) => {
    setDraft((current) => ({
      ...current,
      requirements: current.requirements.map((requirement, position) =>
        position === index ? { ...requirement, [field]: value } : requirement,
      ),
    }));
    setPreview(null);
  };

  const toggleIdentityType = (type: IdentityType) => {
    setDraft((current) => ({
      ...current,
      identityTypes: current.identityTypes.includes(type)
        ? current.identityTypes.filter((candidate) => candidate !== type)
        : [...current.identityTypes, type],
    }));
    setPreview(null);
  };

  return (
    <div className="rule-builder-layout">
      <form className="panel rule-builder" onSubmit={saveRule}>
        <div className="panel-title">
          <div>
            <p>VISUAL RULE BUILDER</p>
            <h2>Define a dangerous privilege combination</h2>
          </div>
          <ShieldCheck size={21} />
        </div>
        <p className="muted">
          Conditions are joined with AND. Comma-separated permissions inside one condition are
          alternatives joined with OR.
        </p>

        <div className="builder-grid">
          <label>
            Rule title
            <input
              onChange={(event) => setDraft({ ...draft, title: event.target.value })}
              placeholder="Audit shutdown and log deletion"
              value={draft.title}
            />
          </label>
          <label>
            Category
            <select
              onChange={(event) => setDraft({ ...draft, category: event.target.value as Category })}
              value={draft.category}
            >
              <option value="SEGREGATION_OF_DUTIES">Segregation of duties</option>
              <option value="CROSS_PLATFORM_CONTROL">Cross-platform control</option>
              <option value="SUPPLY_CHAIN_PIVOT">Supply-chain pivot</option>
              <option value="DATA_CONTROL_CONFLICT">Data control conflict</option>
            </select>
          </label>
          <label>
            Severity
            <select
              onChange={(event) => setDraft({ ...draft, severity: event.target.value as Severity })}
              value={draft.severity}
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </label>
          <label>
            Minimum platforms
            <input
              min="2"
              onChange={(event) => setDraft({ ...draft, minimumPlatforms: event.target.value })}
              placeholder="Optional"
              type="number"
              value={draft.minimumPlatforms}
            />
          </label>
        </div>

        <label>
          Dangerous capability
          <textarea
            onChange={(event) => setDraft({ ...draft, description: event.target.value })}
            placeholder="Explain why these privileges are dangerous when held together."
            value={draft.description}
          />
        </label>

        <fieldset className="identity-scope">
          <legend>Apply to</legend>
          {(['HUMAN', 'SERVICE_ACCOUNT', 'WORKLOAD'] as IdentityType[]).map((type) => (
            <button
              className={draft.identityTypes.includes(type) ? 'selected' : ''}
              key={type}
              onClick={() => toggleIdentityType(type)}
              type="button"
            >
              {type === 'HUMAN'
                ? 'Users'
                : type === 'SERVICE_ACCOUNT'
                  ? 'Service accounts'
                  : 'Workloads'}
            </button>
          ))}
        </fieldset>

        <div className="condition-heading">
          <div>
            <span>Match every condition</span>
            <small>Each condition must have supporting effective-access evidence.</small>
          </div>
          <button
            className="secondary-action"
            onClick={() =>
              setDraft((current) => ({
                ...current,
                requirements: [
                  ...current.requirements,
                  blankRequirement(current.requirements.length + 1),
                ],
              }))
            }
            type="button"
          >
            <Plus size={15} /> Add condition
          </button>
        </div>

        <div className="condition-stack">
          {draft.requirements.map((requirement, index) => (
            <article className="rule-condition" key={`${requirement.id}-${index}`}>
              <b>{index > 0 ? 'AND' : 'IF'}</b>
              <label>
                Platform
                <input
                  list="pid-platforms"
                  onChange={(event) => updateRequirement(index, 'platform', event.target.value)}
                  placeholder="AWS"
                  value={requirement.platform}
                />
              </label>
              <label>
                Permission or alternatives
                <input
                  onChange={(event) => updateRequirement(index, 'permissions', event.target.value)}
                  placeholder="cloudtrail:StopLogging"
                  value={requirement.permissions}
                />
              </label>
              <label>
                Resource scope
                <input
                  onChange={(event) =>
                    updateRequirement(index, 'resourcePattern', event.target.value)
                  }
                  placeholder="Optional, supports *"
                  value={requirement.resourcePattern}
                />
              </label>
              {draft.requirements.length > 2 && (
                <button
                  aria-label={`Remove condition ${index + 1}`}
                  className="icon-action"
                  onClick={() =>
                    setDraft((current) => ({
                      ...current,
                      requirements: current.requirements.filter(
                        (_, position) => position !== index,
                      ),
                    }))
                  }
                  type="button"
                >
                  <X size={16} />
                </button>
              )}
            </article>
          ))}
        </div>
        <datalist id="pid-platforms">
          {['AWS', 'Azure', 'GCP', 'Kubernetes', 'GitHub', 'Entra ID', 'Vault', 'Database'].map(
            (platform) => (
              <option key={platform} value={platform} />
            ),
          )}
        </datalist>

        <div className="builder-grid narrative-grid">
          <label>
            Business impact
            <textarea
              onChange={(event) => setDraft({ ...draft, businessImpact: event.target.value })}
              placeholder="What could an attacker or insider accomplish?"
              value={draft.businessImpact}
            />
          </label>
          <label>
            Recommended remediation
            <textarea
              onChange={(event) => setDraft({ ...draft, remediation: event.target.value })}
              placeholder="Which control or privilege change breaks the combination?"
              value={draft.remediation}
            />
          </label>
          <label>
            MITRE ATT&amp;CK mappings
            <input
              onChange={(event) => setDraft({ ...draft, mitreMappings: event.target.value })}
              placeholder="T1078, T1098"
              value={draft.mitreMappings}
            />
          </label>
          <label>
            Control mappings
            <input
              onChange={(event) => setDraft({ ...draft, nistMappings: event.target.value })}
              placeholder="AC-5, AC-6"
              value={draft.nistMappings}
            />
          </label>
        </div>

        {error && <div className="builder-message error">{error}</div>}
        {message && <div className="builder-message success">{message}</div>}

        <div className="builder-actions">
          <button
            className="secondary-action"
            disabled={busy !== null}
            onClick={() => void previewRule()}
            type="button"
          >
            <FlaskConical size={16} /> {busy === 'preview' ? 'Testing…' : 'Test against identities'}
          </button>
          <button className="primary-action" disabled={busy !== null} type="submit">
            <Save size={16} /> {busy === 'save' ? 'Saving…' : 'Save as draft'}
          </button>
        </div>

        {preview && (
          <section className="rule-preview">
            <div>
              <CheckCircle2 size={20} />
              <span>
                <strong>{preview.affectedIdentityCount}</strong> affected identities
                <small>{preview.matchedGrantCount} matched entitlement grants</small>
              </span>
            </div>
            {preview.affectedIdentities.length === 0 ? (
              <p>No current identity matches. The rule can still detect future access changes.</p>
            ) : (
              preview.affectedIdentities.map((identity) => (
                <article key={identity.identityId}>
                  <span>
                    <strong>{identity.displayName}</strong>
                    <small>{identity.identityType.replaceAll('_', ' ')}</small>
                  </span>
                  <p>{identity.matchedPermissions.join(' + ')}</p>
                </article>
              ))
            )}
          </section>
        )}
      </form>

      <section className="panel custom-rule-catalogue">
        <div className="panel-title">
          <div>
            <p>CUSTOM CATALOGUE</p>
            <h2>Customer-defined rules</h2>
          </div>
          <span>{rules.length} rules</span>
        </div>
        <p className="muted">
          Drafts are isolated from detection until a security owner publishes them.
        </p>
        {rules.length === 0 && (
          <div className="empty-custom-rules">
            <ShieldCheck size={26} />
            <strong>No customer rules yet</strong>
            <span>Build and test the first organization-specific combination.</span>
          </div>
        )}
        {rules.map((record) => (
          <article className="custom-rule-card" key={record.id}>
            <div>
              <span className={`rule-status ${record.status.toLowerCase()}`}>{record.status}</span>
              <span className={`severity-pill ${record.rule.severity}`}>
                {record.rule.severity}
              </span>
            </div>
            <strong>{record.rule.title}</strong>
            <small>
              {record.rule.id} · v{record.version}
            </small>
            <p>
              {record.rule.requirements
                .map(({ anyPermissions }) => anyPermissions.join(' OR '))
                .join(' AND ')}
            </p>
            <footer>
              <span>{new Date(record.updatedAt).toLocaleDateString()}</span>
              {record.status === 'DRAFT' && (
                <div>
                  <button
                    aria-label={`Delete ${record.rule.title}`}
                    className="icon-action"
                    disabled={busy !== null}
                    onClick={() => void deleteRule(record.id)}
                  >
                    <Trash2 size={15} />
                  </button>
                  <button
                    className="publish-action"
                    disabled={busy !== null}
                    onClick={() => void publishRule(record.id)}
                  >
                    <Rocket size={15} /> Publish
                  </button>
                </div>
              )}
            </footer>
          </article>
        ))}
      </section>
    </div>
  );
}
