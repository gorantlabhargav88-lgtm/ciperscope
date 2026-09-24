import { useMemo, useState } from 'react';
import type { EvidenceGraphResponse, EvidenceGraphNode, EvidenceGraphNodeType } from '@ciperscope/types';

/**
 * Phase I — Evidence Graph visualization. Deliberately built without a new
 * graph-visualization dependency (the graph is small — bounded server-side
 * to 500 nodes/1000 edges — a plain SVG layout is sufficient and avoids
 * pulling in a heavyweight framework for what this UI actually needs).
 *
 * Layout: nodes are grouped into columns by type (a simple, deterministic,
 * non-overlapping layout — not a force simulation, so it's stable across
 * re-renders of the same graph). EMAIL is always the leftmost column, since
 * every edge in this graph either originates from or traces back to it.
 *
 * Safety: nodes are inert data. Clicking a node only opens a local detail
 * panel — it never navigates to a URL, opens an attachment, or makes any
 * network request. A decoded QR/URL payload is shown as plain text, never
 * as a clickable link.
 */

const COLUMN_ORDER: EvidenceGraphNodeType[] = [
  'CASE', 'EMAIL', 'SENDER', 'RECIPIENT', 'IP', 'ATTACHMENT', 'URL', 'GEOLOCATION', 'DOMAIN',
  'FILE_HASH', 'QR_CODE', 'APK', 'CTI_INDICATOR', 'THREAT_INDICATOR', 'EVIDENCE', 'ALERT',
];

const NODE_COLORS: Record<EvidenceGraphNodeType, string> = {
  CASE: '#c084fc',
  EMAIL: '#818cf8',
  SENDER: '#fda4af',
  RECIPIENT: '#7dd3fc',
  IP: '#38bdf8',
  DOMAIN: '#34d399',
  URL: '#fbbf24',
  ATTACHMENT: '#fb923c',
  FILE_HASH: '#a78bfa',
  QR_CODE: '#22d3ee',
  APK: '#f87171',
  CTI_INDICATOR: '#ef4444',
  GEOLOCATION: '#60a5fa',
  THREAT_INDICATOR: '#f43f5e',
  EVIDENCE: '#facc15',
  ALERT: '#fb7185',
};

const COLUMN_WIDTH = 170;
const ROW_HEIGHT = 56;
const NODE_RADIUS = 8;
const TOP_MARGIN = 30;
const LEFT_MARGIN = 70;

interface LayoutNode extends EvidenceGraphNode {
  x: number;
  y: number;
}

function layoutGraph(nodes: EvidenceGraphNode[]): Map<string, LayoutNode> {
  const byColumn = new Map<EvidenceGraphNodeType, EvidenceGraphNode[]>();
  for (const type of COLUMN_ORDER) byColumn.set(type, []);
  for (const n of nodes) {
    if (!byColumn.has(n.type)) byColumn.set(n.type, []);
    byColumn.get(n.type)!.push(n);
  }

  const positioned = new Map<string, LayoutNode>();
  let colIndex = 0;
  for (const type of COLUMN_ORDER) {
    const colNodes = byColumn.get(type) ?? [];
    colNodes.forEach((n, row) => {
      positioned.set(n.id, {
        ...n,
        x: LEFT_MARGIN + colIndex * COLUMN_WIDTH,
        y: TOP_MARGIN + row * ROW_HEIGHT,
      });
    });
    if (colNodes.length > 0) colIndex++;
  }
  return positioned;
}

/**
 * Reverse DNS (PTR) is attacker-influenceable, honest forensic context —
 * never presented as a verified hostname (see email.routes.ts's Phase N
 * comment and evidenceGraph.ts's node data). Shown only when a lookup has
 * actually happened; "Not resolved" for a real null, never fabricated.
 */
function IpNodeDetail({ data }: { data: Record<string, unknown> }) {
  const reverseDns = data.reverseDns as string[] | null | undefined;
  return (
    <div className="border-t border-slate-800 pt-2">
      <div className="text-slate-500 mb-1">Reverse DNS (PTR)</div>
      {reverseDns && reverseDns.length > 0 ? (
        <div className="space-y-1">
          {reverseDns.map((hostname) => (
            <div key={hostname} className="bg-slate-900 rounded p-1.5 text-slate-300 font-mono break-all">{hostname}</div>
          ))}
        </div>
      ) : (
        <div className="text-slate-600 italic">Not resolved</div>
      )}
    </div>
  );
}

/**
 * RDAP domain intelligence — only present when a real lookup has actually
 * happened (see evidenceGraph.ts's comment on this same field); "Not yet
 * enriched" for a real null, never fabricated registrar/dates.
 */
function DomainNodeDetail({ data }: { data: Record<string, unknown> }) {
  const intel = data.domainIntelligence as {
    status?: string;
    registrar?: string | null;
    registrationDate?: string | null;
    expirationDate?: string | null;
    nameservers?: string[] | null;
    domainStatus?: string[] | null;
  } | null | undefined;

  return (
    <div className="border-t border-slate-800 pt-2">
      <div className="text-slate-500 mb-1">Domain Intelligence (RDAP)</div>
      {intel ? (
        <div className="bg-slate-900 rounded p-2 space-y-1">
          <div className="flex justify-between"><span className="text-slate-500">Status</span><span className="text-slate-300">{intel.status ?? 'Unknown'}</span></div>
          <div className="flex justify-between"><span className="text-slate-500">Registrar</span><span className="text-slate-300 truncate max-w-[140px]">{intel.registrar ?? 'Unknown'}</span></div>
          <div className="flex justify-between"><span className="text-slate-500">Registered</span><span className="text-slate-300">{intel.registrationDate ? new Date(intel.registrationDate).toLocaleDateString() : 'Unknown'}</span></div>
          <div className="flex justify-between"><span className="text-slate-500">Expires</span><span className="text-slate-300">{intel.expirationDate ? new Date(intel.expirationDate).toLocaleDateString() : 'Unknown'}</span></div>
          {intel.nameservers && intel.nameservers.length > 0 && (
            <div className="pt-1 border-t border-slate-800">
              <span className="text-slate-500">Nameservers</span>
              <div className="text-slate-400 mt-0.5">{intel.nameservers.join(', ')}</div>
            </div>
          )}
        </div>
      ) : (
        <div className="text-slate-600 italic">Not yet enriched</div>
      )}
    </div>
  );
}

export function EvidenceGraphView({ graph }: { graph: EvidenceGraphResponse }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const positioned = useMemo(() => layoutGraph(graph.nodes), [graph.nodes]);
  const selected = selectedId ? positioned.get(selectedId) ?? null : null;

  const maxRowsInAnyColumn = useMemo(() => {
    const counts = new Map<EvidenceGraphNodeType, number>();
    for (const n of graph.nodes) counts.set(n.type, (counts.get(n.type) ?? 0) + 1);
    return Math.max(1, ...Array.from(counts.values()));
  }, [graph.nodes]);

  const usedColumns = useMemo(() => new Set(graph.nodes.map((n) => n.type)).size, [graph.nodes]);
  const svgWidth = Math.max(400, LEFT_MARGIN + usedColumns * COLUMN_WIDTH);
  const svgHeight = Math.max(200, TOP_MARGIN + maxRowsInAnyColumn * ROW_HEIGHT + 30);

  if (graph.nodes.length === 0) {
    return <div className="text-xs text-slate-600 text-center py-4">No evidence graph data for this email yet</div>;
  }

  return (
    <div className="flex flex-col md:flex-row gap-4">
      <div className="flex-1 overflow-auto bg-slate-950 border border-slate-800 rounded">
        <svg width={svgWidth} height={svgHeight} className="min-w-full">
          {graph.edges.map((edge) => {
            const from = positioned.get(edge.from);
            const to = positioned.get(edge.to);
            if (!from || !to) return null;
            const isHighlighted = selectedId === edge.from || selectedId === edge.to;
            return (
              <line
                key={edge.id}
                x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                stroke={isHighlighted ? '#94a3b8' : '#334155'}
                strokeWidth={isHighlighted ? 1.5 : 1}
              />
            );
          })}
          {Array.from(positioned.values()).map((node) => (
            <g
              key={node.id}
              transform={`translate(${node.x}, ${node.y})`}
              onClick={() => setSelectedId(node.id)}
              className="cursor-pointer"
            >
              <circle
                r={NODE_RADIUS}
                fill={NODE_COLORS[node.type] ?? '#94a3b8'}
                stroke={selectedId === node.id ? '#f8fafc' : 'transparent'}
                strokeWidth={2}
              />
              <text x={NODE_RADIUS + 6} y={4} fontSize={10} fill="#cbd5e1">
                {node.label.length > 24 ? `${node.label.slice(0, 24)}…` : node.label}
              </text>
            </g>
          ))}
        </svg>
      </div>

      <div className="w-full md:w-72 flex-shrink-0 bg-slate-950 border border-slate-800 rounded p-3 text-xs space-y-2">
        {!selected ? (
          <div className="text-slate-600">Click a node to inspect its evidence and provenance.</div>
        ) : (
          <>
            <div className="flex items-center justify-between">
              <span className="font-medium text-slate-200">{selected.type}</span>
              <span className="text-[10px] text-slate-600">{selected.id}</span>
            </div>
            <div className="text-slate-300 break-all font-mono">{selected.label}</div>
            {selected.type === 'IP' && <IpNodeDetail data={selected.data} />}
            {selected.type === 'DOMAIN' && <DomainNodeDetail data={selected.data} />}

            <div className="border-t border-slate-800 pt-2">
              <div className="text-slate-500 mb-1">Evidence</div>
              <pre className="whitespace-pre-wrap break-all text-slate-400 bg-slate-900 rounded p-2 max-h-40 overflow-auto">
                {JSON.stringify(selected.data, null, 2)}
              </pre>
            </div>
            <div className="border-t border-slate-800 pt-2">
              <div className="text-slate-500 mb-1">Provenance ({selected.provenance.length})</div>
              <div className="space-y-1">
                {selected.provenance.map((p, i) => (
                  <div key={i} className="bg-slate-900 rounded p-1.5">
                    <div className="text-slate-300">{p.source}</div>
                    {p.sourceRecordId && <div className="text-slate-600 truncate">ref: {p.sourceRecordId}</div>}
                    {p.confidence != null && <div className="text-slate-600">confidence: {p.confidence}</div>}
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
