'use client';

import {
  Background,
  BaseEdge,
  Controls,
  MarkerType,
  ReactFlow,
  ReactFlowProvider,
  getBezierPath,
  useReactFlow,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
  Handle,
  Position,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Database, Diamond, Shield, Zap, type LucideIcon } from 'lucide-react';
import { useEffect, useMemo, useRef, type RefObject } from 'react';

type PathTone = 'identity' | 'role' | 'warning' | 'danger';
export type AttackPathDirection = 'forward' | 'reverse';

interface AttackPathNodeData {
  label: string;
  tone: PathTone;
  selected: boolean;
  onPath: boolean;
  [key: string]: unknown;
}

interface ColumnHeaderData {
  label: string;
  [key: string]: unknown;
}

interface FlowEdgeData {
  active: boolean;
  [key: string]: unknown;
}

const NODE_WIDTH = 208;
const NODE_HEIGHT = 62;
const COLUMN_WIDTH = 300;
const ROW_HEIGHT = 108;
const ORIGIN_X = 48;
const ORIGIN_Y = 68;
const HEADER_OFFSET = 46;

// Particle travels at a roughly constant on-screen speed regardless of edge length.
const PARTICLE_SPEED = 150; // px per second
const PARTICLE_MIN_DURATION = 0.9; // seconds
const PARTICLE_MAX_DURATION = 4; // seconds

const TONE_ICON: Record<PathTone, LucideIcon> = {
  identity: Diamond,
  role: Shield,
  warning: Zap,
  danger: Database,
};

function toneForDepth(depth: number, isLeaf: boolean, direction: AttackPathDirection): PathTone {
  if (direction === 'reverse') {
    if (depth === 0) return 'danger';
    if (isLeaf) return 'identity';
    if (depth <= 1) return 'warning';
    return 'role';
  }
  if (depth === 0) return 'identity';
  if (isLeaf) return 'danger';
  if (depth >= 2) return 'warning';
  return 'role';
}

function columnHeaderLabel(
  column: number,
  maxColumn: number,
  direction: AttackPathDirection,
): string {
  if (direction === 'reverse') {
    if (column === 0) return 'Compromised asset';
    if (column === maxColumn) return 'Source identity';
    if (column <= 1) return 'Pivot / privilege';
    return 'Role / platform';
  }
  if (column === 0) return 'Identity';
  if (column === maxColumn) return 'Target resource';
  if (column >= 2) return 'Privilege';
  return 'Role / platform';
}

function AttackPathNode({ data }: NodeProps) {
  const nodeData = data as AttackPathNodeData;
  const Icon = TONE_ICON[nodeData.tone];
  return (
    <div
      className={`apx-node tone-${nodeData.tone} ${nodeData.selected ? 'selected' : ''} ${
        nodeData.onPath ? 'on-path' : ''
      }`}
    >
      <Handle type="target" position={Position.Left} className="apx-handle" />
      <span className="apx-accent" />
      <span className="apx-icon">
        <Icon size={16} />
      </span>
      <span className="apx-label" title={nodeData.label}>
        {nodeData.label}
      </span>
      <span className="apx-dot" aria-hidden="true" />
      <Handle type="source" position={Position.Right} className="apx-handle" />
    </div>
  );
}

function ColumnHeaderNode({ data }: NodeProps) {
  const headerData = data as ColumnHeaderData;
  return <div className="apx-col-header">{headerData.label}</div>;
}

/** Bezier edge with a continuously looping glowing particle moving source -> target. */
function FlowEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style,
  markerEnd,
  data,
}: EdgeProps) {
  const [edgePath] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const active = (data as FlowEdgeData | undefined)?.active ?? false;

  // Constant-speed particle: duration scales with the edge's straight-line span.
  const distance = Math.hypot(targetX - sourceX, targetY - sourceY);
  const duration = Math.min(
    PARTICLE_MAX_DURATION,
    Math.max(PARTICLE_MIN_DURATION, distance / PARTICLE_SPEED),
  );

  return (
    <>
      <BaseEdge id={id} path={edgePath} style={style} markerEnd={markerEnd} />
      <circle className={`apx-flow-particle ${active ? 'active' : ''}`} r={3.2}>
        <animateMotion dur={`${duration}s`} repeatCount="indefinite" path={edgePath} />
      </circle>
    </>
  );
}

const nodeTypes = { attackPath: AttackPathNode, columnHeader: ColumnHeaderNode };
const edgeTypes = { flow: FlowEdge };

function buildAdjacency(orientedPaths: string[][]) {
  const children = new Map<string, Set<string>>();
  const depth = new Map<string, number>();
  const roots: string[] = [];
  const rootSeen = new Set<string>();

  for (const path of orientedPaths) {
    if (path.length === 0) continue;
    if (!rootSeen.has(path[0])) {
      rootSeen.add(path[0]);
      roots.push(path[0]);
    }
    path.forEach((label, index) => {
      const currentDepth = depth.get(label);
      if (currentDepth === undefined || index < currentDepth) depth.set(label, index);
      if (index === 0) return;
      const parent = path[index - 1];
      const bucket = children.get(parent) ?? new Set<string>();
      bucket.add(label);
      children.set(parent, bucket);
    });
  }

  return { children, depth, roots };
}

/** Lays out the entire tree/DAG at once — no expansion state, every node is visible. */
function layoutFullTree(
  roots: string[],
  children: Map<string, Set<string>>,
  depth: Map<string, number>,
  selectedNode: string | null,
  direction: AttackPathDirection,
  activePathLabels: Set<string>,
) {
  const columnBuckets = new Map<number, string[]>();
  const ordered: string[] = [];
  const seen = new Set<string>();

  const walk = (label: string) => {
    if (seen.has(label)) return;
    seen.add(label);
    ordered.push(label);
    const column = depth.get(label) ?? 0;
    const bucket = columnBuckets.get(column) ?? [];
    bucket.push(label);
    columnBuckets.set(column, bucket);
    for (const child of children.get(label) ?? []) walk(child);
  };
  roots.forEach(walk);

  const maxColumn = Math.max(0, ...[...columnBuckets.keys()]);
  const nodes: Node<AttackPathNodeData | ColumnHeaderData>[] = [];
  const nodeIds = new Map<string, string>();

  ordered.forEach((label, index) => {
    const id = `n-${index}`;
    nodeIds.set(label, id);
    const childSet = children.get(label) ?? new Set<string>();
    const isLeaf = childSet.size === 0;
    const column = depth.get(label) ?? 0;
    const row = (columnBuckets.get(column) ?? []).indexOf(label);
    const tone = toneForDepth(column, isLeaf, direction);
    nodes.push({
      id,
      type: 'attackPath',
      position: {
        x: ORIGIN_X + column * COLUMN_WIDTH,
        y: ORIGIN_Y + Math.max(0, row) * ROW_HEIGHT,
      },
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
      data: {
        label,
        tone,
        selected: selectedNode === label,
        onPath: activePathLabels.has(label),
      },
    });
  });

  // Column captions aligned above each occupied column (pan/zoom with the graph).
  for (const column of columnBuckets.keys()) {
    nodes.push({
      id: `header-${column}`,
      type: 'columnHeader',
      position: { x: ORIGIN_X + column * COLUMN_WIDTH, y: ORIGIN_Y - HEADER_OFFSET },
      width: NODE_WIDTH,
      height: 20,
      selectable: false,
      draggable: false,
      data: { label: columnHeaderLabel(column, maxColumn, direction) },
    });
  }

  const edges: Edge[] = [];
  for (const [parent, childSet] of children) {
    const source = nodeIds.get(parent);
    if (!source) continue;
    for (const child of childSet) {
      const target = nodeIds.get(child);
      if (!target) continue;
      const active = activePathLabels.has(parent) && activePathLabels.has(child);
      edges.push({
        id: `${source}->${target}`,
        source,
        target,
        type: 'flow',
        className: active ? 'apx-edge active' : 'apx-edge',
        data: { active },
        style: {
          stroke: active ? '#2f61ed' : '#cbd3e1',
          strokeWidth: active ? 2.4 : 1.4,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: active ? '#2f61ed' : '#cbd3e1',
          width: 15,
          height: 15,
        },
      });
    }
  }

  return { nodes, edges };
}

function computeCenteredViewport(
  nodes: Array<Pick<Node, 'position'> & { width?: number | null; height?: number | null }>,
  containerWidth: number,
  containerHeight: number,
) {
  if (nodes.length === 0 || containerWidth < 48 || containerHeight < 48) return null;

  let minX = Number.POSITIVE_INFINITY;
  let minY = Number.POSITIVE_INFINITY;
  let maxX = Number.NEGATIVE_INFINITY;
  let maxY = Number.NEGATIVE_INFINITY;

  for (const node of nodes) {
    const width = node.width ?? NODE_WIDTH;
    const height = node.height ?? NODE_HEIGHT;
    minX = Math.min(minX, node.position.x);
    minY = Math.min(minY, node.position.y);
    maxX = Math.max(maxX, node.position.x + width);
    maxY = Math.max(maxY, node.position.y + height);
  }

  const graphWidth = Math.max(maxX - minX, 1);
  const graphHeight = Math.max(maxY - minY, 1);
  const zoom = Math.min(
    (containerWidth * 0.9) / graphWidth,
    (containerHeight * 0.84) / graphHeight,
    1.2,
  );
  const clampedZoom = Math.min(1.2, Math.max(0.25, zoom));

  return {
    x: (containerWidth - graphWidth * clampedZoom) / 2 - minX * clampedZoom,
    y: (containerHeight - graphHeight * clampedZoom) / 2 - minY * clampedZoom,
    zoom: clampedZoom,
  };
}

/** Centers and fits the full graph on open / path change. */
function InitialViewportFitter({
  resetKey,
  nodes,
  canvasRef,
}: {
  resetKey: string;
  nodes: Node<AttackPathNodeData | ColumnHeaderData>[];
  canvasRef: RefObject<HTMLDivElement | null>;
}) {
  const { setViewport } = useReactFlow();
  const nodesRef = useRef(nodes);
  nodesRef.current = nodes;

  useEffect(() => {
    let cancelled = false;
    const timers: number[] = [];

    const applyFit = () => {
      if (cancelled) return;
      const element = canvasRef.current;
      if (!element || element.clientWidth < 48 || element.clientHeight < 48) return;
      const viewport = computeCenteredViewport(
        nodesRef.current,
        element.clientWidth,
        element.clientHeight,
      );
      if (!viewport) return;
      void setViewport(viewport, { duration: 0 });
    };

    const wait = () => {
      const element = canvasRef.current;
      if (!element) return;
      if (element.clientWidth >= 48 && element.clientHeight >= 48) {
        applyFit();
        return;
      }
      timers.push(window.setTimeout(wait, 32));
    };

    wait();
    timers.push(window.setTimeout(applyFit, 100));

    return () => {
      cancelled = true;
      timers.forEach((timer) => window.clearTimeout(timer));
    };
  }, [resetKey, setViewport, canvasRef]);

  return null;
}

interface AttackPathGraphProps {
  paths: string[][];
  selectedNode: string | null;
  direction?: AttackPathDirection;
  onSelectNode: (node: string) => void;
}

function AttackPathGraphCanvas({
  paths,
  selectedNode,
  direction = 'forward',
  onSelectNode,
}: AttackPathGraphProps) {
  const canvasRef = useRef<HTMLDivElement>(null);

  const graphPaths = useMemo(() => {
    const cleaned = paths.map((path) => path.filter(Boolean)).filter((path) => path.length > 0);
    return (cleaned.length > 0 ? cleaned : [['Identity', 'Role', 'Resource']]).slice(0, 48);
  }, [paths]);

  const orientedPaths = useMemo(
    () => graphPaths.map((path) => (direction === 'reverse' ? [...path].reverse() : path)),
    [graphPaths, direction],
  );

  const { children, depth, roots } = useMemo(
    () => buildAdjacency(orientedPaths),
    [orientedPaths],
  );

  const treeResetKey = useMemo(
    () => `${direction}|${graphPaths.map((path) => path.join('>')).join('|')}`,
    [direction, graphPaths],
  );

  const activePathLabels = useMemo(() => {
    const match =
      selectedNode === null
        ? orientedPaths[0]
        : orientedPaths.find((path) => path.includes(selectedNode)) ?? orientedPaths[0];
    return new Set(match ?? []);
  }, [orientedPaths, selectedNode]);

  const { nodes, edges } = useMemo(
    () => layoutFullTree(roots, children, depth, selectedNode, direction, activePathLabels),
    [roots, children, depth, selectedNode, direction, activePathLabels],
  );

  return (
    <div className="attack-graph-shell">
      <div className="attack-graph-legend">
        {direction === 'reverse' ? (
          <>
            <span className="tone-danger">Compromised asset</span>
            <span className="tone-warning">Pivot / privilege</span>
            <span className="tone-role">Role / platform</span>
            <span className="tone-identity">Likely source identity</span>
          </>
        ) : (
          <>
            <span className="tone-identity">Identity</span>
            <span className="tone-role">Role / platform</span>
            <span className="tone-warning">Privilege</span>
            <span className="tone-danger">Target resource</span>
          </>
        )}
        <span className="attack-graph-hint"></span>
      </div>
      <div className="attack-graph-canvas" ref={canvasRef}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          minZoom={0.25}
          maxZoom={1.6}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable
          onlyRenderVisibleElements
          panOnScroll
          zoomOnScroll
          proOptions={{ hideAttribution: true }}
          onNodeClick={(_, node) => {
            if (node.type !== 'attackPath') return;
            const data = node.data as AttackPathNodeData;
            onSelectNode(data.label);
          }}
        >
          <InitialViewportFitter resetKey={treeResetKey} nodes={nodes} canvasRef={canvasRef} />
          <Background gap={20} size={1.4} color="#dfe4ee" />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    </div>
  );
}

export function AttackPathGraph(props: AttackPathGraphProps) {
  return (
    <ReactFlowProvider>
      <AttackPathGraphCanvas {...props} />
    </ReactFlowProvider>
  );
}
