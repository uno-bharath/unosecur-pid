import { Activity, Bot, Cloud, GitBranch, Search, ShieldAlert, Users } from 'lucide-react';

const identities = [
  {
    name: 'John Smith',
    context: 'Platform Engineering · Human',
    score: 97,
    platforms: 'AWS · Kubernetes · GitHub · Vault',
    finding: 'Cross-control-plane administrator',
  },
  {
    name: 'prod-deploy-bot',
    context: 'Engineering · Workload',
    score: 91,
    platforms: 'GitHub · AWS · Kubernetes',
    finding: 'Long-lived workload credential',
  },
  {
    name: 'Maya Patel',
    context: 'Finance · Human',
    score: 84,
    platforms: 'Entra ID · AWS',
    finding: 'Create vendor + approve payment',
  },
];

const metrics = [
  { label: 'Enterprise risk', value: '86', suffix: '/100', icon: ShieldAlert, tone: 'critical' },
  { label: 'Critical identities', value: '18', suffix: '', icon: Users, tone: 'warning' },
  { label: 'Attack paths', value: '42', suffix: '', icon: GitBranch, tone: 'accent' },
  { label: 'Identities scanned', value: '12,480', suffix: '', icon: Activity, tone: 'neutral' },
];

export default function Dashboard() {
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
            <ShieldAlert size={18} /> Findings <b>18</b>
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
          <i /> Local AI online<small>Ollama · qwen3:4b</small>
        </div>
      </aside>

      <section className="content">
        <header>
          <div>
            <p>SECURITY POSTURE</p>
            <h1>Good evening, Security Team</h1>
            <span>Here is what needs your attention across the enterprise.</span>
          </div>
          <div className="search">
            <Search size={18} />
            <span>Search identities, findings…</span>
            <kbd>⌘ K</kbd>
          </div>
        </header>

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
                {label === 'Enterprise risk' ? '↑ 4 points this week' : 'Live enterprise snapshot'}
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
              <button>View all</button>
            </div>
            {identities.map((identity) => (
              <div className="identity" key={identity.name}>
                <div className="avatar">{identity.name.slice(0, 2).toUpperCase()}</div>
                <div className="identity-copy">
                  <strong>{identity.name}</strong>
                  <small>{identity.context}</small>
                  <span>{identity.finding}</span>
                </div>
                <div className="platforms">{identity.platforms}</div>
                <div className="score">
                  {identity.score}
                  <small>RISK</small>
                </div>
              </div>
            ))}
          </article>

          <article className="panel copilot">
            <div className="panel-title">
              <div>
                <p>LOCAL AI</p>
                <h2>
                  <Bot size={20} /> Investigation copilot
                </h2>
              </div>
              <i />
            </div>
            <div className="prompt">Why is John Smith a toxic identity?</div>
            <div className="answer">
              <strong>John creates a complete infrastructure takeover path.</strong>
              <p>
                Three independently critical findings connect source control, AWS production,
                Kubernetes administration, and Vault secrets.
              </p>
              <ul>
                <li>Affects 8 cloud accounts and 12 clusters</li>
                <li>Exposes 180 secrets and 4 databases</li>
                <li>Risk confidence: 96%</li>
              </ul>
            </div>
            <button className="ask">
              Ask a security question <span>→</span>
            </button>
          </article>

          <article className="panel path">
            <div className="panel-title">
              <div>
                <p>CRITICAL PATH</p>
                <h2>Identity → customer data</h2>
              </div>
              <button>Investigate</button>
            </div>
            <div className="nodes">
              {[
                'John Smith',
                'GitHub Owner',
                'AWS Prod Role',
                'EKS Admin',
                'Vault Secrets',
                'Customer DB',
              ].map((node, index) => (
                <div className={index === 0 || index === 5 ? 'node danger' : 'node'} key={node}>
                  <span>{node}</span>
                  {index < 5 && <b>→</b>}
                </div>
              ))}
            </div>
          </article>
        </div>
      </section>
    </main>
  );
}
