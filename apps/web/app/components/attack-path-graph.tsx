'use client';

import {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  Handle,
  Position,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useMemo } from 'react';

type PathTone = 'identity' | 'role' | 'warning' | 'danger';

interface AttackPathNodeData {
  label: string;
  tone: PathTone;
  selected: boolean;
  [key: string]: unknown;
}

function toneForIndex(index: number, total: number): PathTone {
  if (index === 0) return 'identity';
  if (index === total - 1) return 'danger';
  if (index >= total - 2) return 'warning';
  return 'role';
}

function AttackPathNode({ data }: NodeProps) {
  const nodeData = data as AttackPathNodeData;
  return (
    <div
      className={`attack-graph-node tone-${nodeData.tone} ${nodeData.selected ? 'selected' : ''}`}
    >
      <Handle type="target" position={Position.Left} className="attack-graph-handle" />
      <span>{nodeData.label}</span>
      <Handle type="source" position={Position.Right} className="attack-graph-handle" />
    </div>
  );
}

const nodeTypes = { attackPath: AttackPathNode };

function buildGraph(paths: string[][], selectedNode: string | null) {
  const nodeIds = new Map<string, string>();
  const nodes: Node<AttackPathNodeData>[] = [];
  const edgeKeys = new Set<string>();
  const edges: Edge[] = [];
  const columnBuckets = new Map<number, string[]>();

  paths.forEach((path) => {
    path.forEach((label, index) => {
      if (!nodeIds.has(label)) {
        const id = `n-${nodeIds.size}`;
        nodeIds.set(label, id);
        const bucket = columnBuckets.get(index) ?? [];
        bucket.push(label);
        columnBuckets.set(index, bucket);
        nodes.push({
          id,
          type: 'attackPath',
          position: { x: 0, y: 0 },
          data: {
            label,
            tone: toneForIndex(index, path.length),
            selected: selectedNode === label,
          },
        });
      } else {
        const existing = nodes.find((node) => node.id === nodeIds.get(label));
        if (existing && selectedNode === label) {
          existing.data = { ...existing.data, selected: true };
        }
      }

      if (index > 0) {
        const source = nodeIds.get(path[index - 1]);
        const target = nodeIds.get(label);
        if (!source || !target) return;
        const key = `${source}->${target}`;
        if (edgeKeys.has(key)) return;
        edgeKeys.add(key);
        const active =
          selectedNode !== null && (path[index - 1] === selectedNode || label === selectedNode);
        edges.push({
          id: key,
          source,
          target,
          animated: active,
          className: active ? 'attack-graph-edge active' : 'attack-graph-edge',
          style: {
            stroke: active ? '#2f61ed' : '#c5ccd9',
            strokeWidth: active ? 2.4 : 1.5,
            opacity: selectedNode && !active ? 0.35 : 1,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: active ? '#2f61ed' : '#c5ccd9',
            width: 16,
            height: 16,
          },
        });
      }
    });
  });

  const columnWidth = 210;
  const rowHeight = 88;
  columnBuckets.forEach((labels, column) => {
    labels.forEach((label, row) => {
      const id = nodeIds.get(label);
      const node = nodes.find((item) => item.id === id);
      if (!node) return;
      const offsetY = ((labels.length - 1) * rowHeight) / -2;
      node.position = {
        x: column * columnWidth,
        y: offsetY + row * rowHeight,
      };
    });
  });

  return { nodes, edges };
}

interface AttackPathGraphProps {
  paths: string[][];
  selectedNode: string | null;
  onSelectNode: (node: string) => void;
}

export function AttackPathGraph({ paths, selectedNode, onSelectNode }: AttackPathGraphProps) {
  const graphPaths = useMemo(() => {
    const cleaned = paths.map((path) => path.filter(Boolean)).filter((path) => path.length > 0);
    return cleaned.length > 0 ? cleaned : [['Identity', 'Role', 'Resource']];
  }, [paths]);

  const { nodes, edges } = useMemo(
    () => buildGraph(graphPaths, selectedNode),
    [graphPaths, selectedNode],
  );

  return (
    <div className="attack-graph-shell">
      <div className="attack-graph-legend">
        <span className="tone-identity">Identity</span>
        <span className="tone-role">Role / platform</span>
        <span className="tone-warning">Warning</span>
        <span className="tone-danger">Critical asset</span>
      </div>
      <div className="attack-graph-canvas">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.55}
          maxZoom={1.4}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable
          panOnScroll
          proOptions={{ hideAttribution: true }}
          onNodeClick={(_, node) => {
            const label = (node.data as AttackPathNodeData).label;
            onSelectNode(label);
          }}
        >
          <Background gap={18} color="#e6eaf2" />
          <MiniMap
            pannable
            zoomable
            nodeStrokeWidth={2}
            maskColor="rgba(246, 247, 252, 0.7)"
            className="attack-graph-minimap"
          />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    </div>
  );
}
