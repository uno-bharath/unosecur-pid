'use client';

import { ArrowDownRight, ArrowUpRight, ShieldCheck, Sparkles } from 'lucide-react';
import { useMemo, useState } from 'react';

export interface PostureTrendPoint {
  date: string;
  toxicIdentities: number;
  totalConflicts: number;
  criticalConflicts: number;
  newConflicts: number;
  remediatedConflicts: number;
  attackPaths: number;
}

export interface ExecutivePostureTrend {
  periodDays: number;
  points: PostureTrendPoint[];
  summary: {
    toxicIdentityChange: number;
    toxicIdentityChangePercent: number;
    conflictsRemediated: number;
    newConflicts: number;
    netConflictChange: number;
    remediationEfficiency: number;
  };
}

export interface ImmunityWindow {
  days: number;
  toxicIdentityChangePercent: number;
  immunityGainPercent: number;
}

interface ExecutiveTrendChartProps {
  loading: boolean;
  range: number;
  trend: ExecutivePostureTrend | null;
  immunityWindows?: ImmunityWindow[];
  onRangeChange: (days: number) => void;
}

const width = 960;
const height = 420;
const margin = { left: 48, right: 24, top: 28, bottom: 46 };
const immunityPeriods = [7, 15, 30] as const;

export function immunityGainFromToxicMovement(toxicIdentityChangePercent: number): number {
  return Math.max(-100, Math.min(100, -toxicIdentityChangePercent));
}

export function toImmunityWindow(trend: ExecutivePostureTrend): ImmunityWindow {
  const toxicIdentityChangePercent = trend.summary.toxicIdentityChangePercent;
  return {
    days: trend.periodDays,
    toxicIdentityChangePercent,
    immunityGainPercent: immunityGainFromToxicMovement(toxicIdentityChangePercent),
  };
}

function buildSmoothPath(points: Array<{ x: number; y: number }>): string {
  if (points.length === 0) return '';
  return points.reduce((path, point, index) => {
    if (index === 0) return `M ${point.x} ${point.y}`;
    const previous = points[index - 1];
    const controlX = (previous.x + point.x) / 2;
    return `${path} C ${controlX} ${previous.y}, ${controlX} ${point.y}, ${point.x} ${point.y}`;
  }, '');
}

function immunityTone(gain: number): 'gained' | 'lost' | 'flat' {
  if (gain > 0) return 'gained';
  if (gain < 0) return 'lost';
  return 'flat';
}

export function ExecutiveTrendChart({
  loading,
  range,
  trend,
  immunityWindows = [],
  onRangeChange,
}: ExecutiveTrendChartProps) {
  const [activeIndex, setActiveIndex] = useState<number | null>(null);
  const chart = useMemo(() => {
    const points = trend?.points ?? [];
    if (points.length === 0) return null;
    const plotWidth = width - margin.left - margin.right;
    const plotHeight = height - margin.top - margin.bottom;
    const maxToxic = Math.max(...points.map(({ toxicIdentities }) => toxicIdentities), 1) + 1;
    const maxRemediated = Math.max(
      ...points.map(({ remediatedConflicts }) => remediatedConflicts),
      1,
    );
    const xFor = (index: number) =>
      margin.left + (index / Math.max(points.length - 1, 1)) * plotWidth;
    const yFor = (value: number) =>
      margin.top + plotHeight - (value / maxToxic) * (plotHeight - 12);
    const linePoints = points.map((point, index) => ({
      x: xFor(index),
      y: yFor(point.toxicIdentities),
    }));
    return {
      points,
      linePoints,
      linePath: buildSmoothPath(linePoints),
      areaPath: `${buildSmoothPath(linePoints)} L ${linePoints.at(-1)?.x ?? 0} ${
        margin.top + plotHeight
      } L ${linePoints[0]?.x ?? 0} ${margin.top + plotHeight} Z`,
      maxToxic,
      maxRemediated,
      plotHeight,
      xFor,
    };
  }, [trend]);
  const activePoint =
    chart && activeIndex !== null ? chart.points[activeIndex] : chart?.points.at(-1);
  const improving = (trend?.summary.toxicIdentityChange ?? 0) <= 0;
  const DirectionIcon = improving ? ArrowDownRight : ArrowUpRight;
  const selectedImmunityGain = immunityGainFromToxicMovement(
    trend?.summary.toxicIdentityChangePercent ?? 0,
  );
  const windows = immunityPeriods.map((days) => {
    const match = immunityWindows.find((window) => window.days === days);
    if (match) return match;
    if (trend?.periodDays === days) {
      return toImmunityWindow(trend);
    }
    return {
      days,
      toxicIdentityChangePercent: 0,
      immunityGainPercent: 0,
    };
  });
  const windowAnalytics = useMemo(() => {
    const points = trend?.points ?? [];
    if (points.length === 0) {
      return {
        peakToxic: 0,
        troughToxic: 0,
        avgToxic: 0,
        avgRemediated: 0,
        daysWithRemediation: 0,
        criticalShare: 0,
      };
    }
    const toxicValues = points.map((point) => point.toxicIdentities);
    const remediated = points.map((point) => point.remediatedConflicts);
    const critical = points.reduce((sum, point) => sum + point.criticalConflicts, 0);
    const total = points.reduce((sum, point) => sum + point.totalConflicts, 0);
    return {
      peakToxic: Math.max(...toxicValues),
      troughToxic: Math.min(...toxicValues),
      avgToxic: Math.round(toxicValues.reduce((sum, value) => sum + value, 0) / points.length),
      avgRemediated: Number(
        (remediated.reduce((sum, value) => sum + value, 0) / points.length).toFixed(1),
      ),
      daysWithRemediation: remediated.filter((value) => value > 0).length,
      criticalShare: total > 0 ? Math.round((critical / total) * 100) : 0,
    };
  }, [trend]);

  return (
    <article className="panel executive-trend">
      <div className="executive-trend-header">
        <div>
          <p>EXECUTIVE RISK TREND</p>
          <h2>Toxic identities and remediation impact</h2>
          <span>
            {range}-day effective-access evaluation across connected control planes with time-window
            analytics.
          </span>
        </div>
        <div className="trend-ranges" aria-label="Trend period">
          {[7, 15, 30, 90].map((days) => (
            <button
              className={range === days ? 'active' : ''}
              key={days}
              onClick={() => onRangeChange(days)}
              type="button"
            >
              {days}D
            </button>
          ))}
        </div>
      </div>

      <div className="trend-analytics-layout">
        <section className="immunity-gain" aria-label="Enterprise immunity gain">
          <div className="immunity-gain-header">
            <div>
              <p>TIME DURATION WINDOW</p>
              <h3>Posture improvement across comparison windows</h3>
            </div>
            <span>
              Selected {range}D · {selectedImmunityGain > 0 ? '+' : ''}
              {selectedImmunityGain}%
            </span>
          </div>
          <div className="immunity-gain-grid">
            {windows.map((window) => {
              const tone = immunityTone(window.immunityGainPercent);
              const WindowIcon =
                window.immunityGainPercent > 0
                  ? ArrowDownRight
                  : window.immunityGainPercent < 0
                    ? ArrowUpRight
                    : ShieldCheck;
              return (
                <button
                  type="button"
                  key={window.days}
                  className={`immunity-card ${tone} ${range === window.days ? 'active' : ''}`}
                  onClick={() => onRangeChange(window.days)}
                >
                  <span className="immunity-period">{window.days} days</span>
                  <strong>
                    <WindowIcon size={16} aria-hidden />
                    {window.immunityGainPercent > 0 ? '+' : ''}
                    {window.immunityGainPercent}%
                  </strong>
                  <small>
                    {tone === 'gained'
                      ? 'Immunity gained'
                      : tone === 'lost'
                        ? 'Immunity eroded'
                        : 'No net change'}
                  </small>
                  <em>
                    Toxic identities {window.toxicIdentityChangePercent > 0 ? '+' : ''}
                    {window.toxicIdentityChangePercent}%
                  </em>
                </button>
              );
            })}
          </div>
          <div className="window-analytics">
            <div>
              <span>Peak toxic identities</span>
              <strong>{windowAnalytics.peakToxic}</strong>
            </div>
            <div>
              <span>Trough / current floor</span>
              <strong>{windowAnalytics.troughToxic}</strong>
            </div>
            <div>
              <span>Average daily toxic</span>
              <strong>{windowAnalytics.avgToxic}</strong>
            </div>
            <div>
              <span>Avg remediated / day</span>
              <strong>{windowAnalytics.avgRemediated}</strong>
            </div>
            <div>
              <span>Days with remediation</span>
              <strong>
                {windowAnalytics.daysWithRemediation}/{trend?.points.length ?? 0}
              </strong>
            </div>
            <div>
              <span>Critical share</span>
              <strong>{windowAnalytics.criticalShare}%</strong>
            </div>
          </div>
        </section>

        <div className="trend-summary">
          <div>
            <span>Toxic identity movement</span>
            <strong className={improving ? 'positive' : 'negative'}>
              <DirectionIcon size={18} />
              {Math.abs(trend?.summary.toxicIdentityChangePercent ?? 0)}%
            </strong>
            <small>{improving ? 'Risk reduced' : 'Requires attention'}</small>
          </div>
          <div>
            <span>Conflicts remediated</span>
            <strong>{trend?.summary.conflictsRemediated ?? '–'}</strong>
            <small>Permissions removed or separated</small>
          </div>
          <div>
            <span>Remediation efficiency</span>
            <strong>{trend?.summary.remediationEfficiency ?? '–'}%</strong>
            <small>Resolved versus newly detected</small>
          </div>
          <div>
            <span>Net conflict movement</span>
            <strong
              className={(trend?.summary.netConflictChange ?? 0) <= 0 ? 'positive' : 'negative'}
            >
              {(trend?.summary.netConflictChange ?? 0) > 0 ? '+' : ''}
              {trend?.summary.netConflictChange ?? '–'}
            </strong>
            <small>Open findings in selected period</small>
          </div>
        </div>
      </div>

      <div className={`trend-chart-shell ${loading ? 'loading' : ''}`}>
        {chart ? (
          <>
            <svg
              aria-label={`${range}-day toxic identity trend`}
              role="img"
              viewBox={`0 0 ${width} ${height}`}
              preserveAspectRatio="none"
            >
              <defs>
                <linearGradient id="toxic-area" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="0%" stopColor="#2f61ed" stopOpacity="0.22" />
                  <stop offset="100%" stopColor="#2f61ed" stopOpacity="0.01" />
                </linearGradient>
                <filter id="trend-glow">
                  <feGaussianBlur result="blur" stdDeviation="3" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>
              {[0.25, 0.5, 0.75, 1].map((ratio) => {
                const y = margin.top + chart.plotHeight * ratio;
                return (
                  <line
                    className="trend-gridline"
                    key={ratio}
                    x1={margin.left}
                    x2={width - margin.right}
                    y1={y}
                    y2={y}
                  />
                );
              })}
              {chart.points.map((point, index) => {
                const x = chart.xFor(index);
                const barHeight =
                  (point.remediatedConflicts / chart.maxRemediated) * (chart.plotHeight * 0.28);
                return (
                  <rect
                    className="remediation-bar"
                    height={barHeight}
                    key={`bar-${point.date}`}
                    rx="3"
                    width={Math.max(3, 16 - range / 8)}
                    x={x - Math.max(3, 16 - range / 8) / 2}
                    y={margin.top + chart.plotHeight - barHeight}
                  />
                );
              })}
              <path className="trend-area" d={chart.areaPath} />
              <path className="trend-line" d={chart.linePath} filter="url(#trend-glow)" />
              {chart.linePoints.map((point, index) => (
                <g key={`point-${chart.points[index].date}`}>
                  <circle
                    className={`trend-hit ${activeIndex === index ? 'active' : ''}`}
                    cx={point.x}
                    cy={point.y}
                    onMouseEnter={() => setActiveIndex(index)}
                    onMouseLeave={() => setActiveIndex(null)}
                    r={range <= 15 ? 10 : 7}
                  />
                  {(range <= 15 || activeIndex === index || index === chart.points.length - 1) && (
                    <circle className="trend-dot" cx={point.x} cy={point.y} r="4" />
                  )}
                </g>
              ))}
              {chart.points.map((point, index) => {
                const interval = Math.max(1, Math.floor(chart.points.length / 6));
                if (index % interval !== 0 && index !== chart.points.length - 1) return null;
                return (
                  <text
                    className="trend-axis-label"
                    key={`label-${point.date}`}
                    textAnchor="middle"
                    x={chart.xFor(index)}
                    y={height - 14}
                  >
                    {new Date(point.date).toLocaleDateString(undefined, {
                      day: 'numeric',
                      month: 'short',
                    })}
                  </text>
                );
              })}
            </svg>
            {activePoint && (
              <div className="trend-tooltip" aria-live="polite">
                <span>
                  {new Date(activePoint.date).toLocaleDateString(undefined, {
                    day: 'numeric',
                    month: 'short',
                    year: 'numeric',
                  })}
                </span>
                <strong>{activePoint.toxicIdentities} toxic identities</strong>
                <small>
                  {activePoint.totalConflicts} conflicts · {activePoint.remediatedConflicts}{' '}
                  remediated · {activePoint.criticalConflicts} critical
                </small>
              </div>
            )}
            <div className="trend-legend">
              <span>
                <i className="identity-line" /> Toxic identities
              </span>
              <span>
                <i className="remediation-column" /> Remediated conflicts
              </span>
              <span>
                <ShieldCheck size={13} /> {range}D window · evidence-backed snapshot
              </span>
            </div>
          </>
        ) : (
          <div className="trend-empty">
            <Sparkles size={19} />
            Historical posture is being prepared.
          </div>
        )}
      </div>
    </article>
  );
}
