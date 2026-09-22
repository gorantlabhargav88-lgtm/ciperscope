/**
 * Phase I — deterministic Evidence Graph builder.
 *
 * A pure function over already-persisted evidence (no DB access, no
 * network calls, no external provider calls here — the route that calls
 * this has already fetched everything). Given the same input rows, it
 * always produces the same nodes/edges in the same order — no randomness,
 * no wall-clock-dependent identity.
 *
 * Design choices, stated explicitly rather than left implicit:
 * - Node identity is deterministic and derived from the evidence itself
 *   (see buildNodeId below), never a random UUID, so the same URL/domain/
 *   IP appearing via multiple sources collapses into one node with
 *   multiple provenance entries (never duplicate nodes).
 * - Edges are deduplicated by (fromId, toId, type) — repeated evidence for
 *   the same relationship adds a provenance entry, never a duplicate edge.
 * - THREAT_INDICATOR nodes are attached to the exact evidence item the
 *   indicator was computed against (a URL or an attachment) — never to a
 *   domain, since domain-level indicators were never actually computed at
 *   that granularity and attaching them there would be an invented
 *   relationship.
 * - Every node/edge carries `provenance`: where this specific fact came
 *   from, never presenting externally-sourced intelligence (CTI/geo) as if
 *   it were directly observed in the email.
 */

export type GraphNodeType =
  | 'EMAIL' | 'DOMAIN' | 'URL' | 'IP' | 'ATTACHMENT' | 'FILE_HASH'
  | 'QR_CODE' | 'APK' | 'CTI_INDICATOR' | 'GEOLOCATION' | 'THREAT_INDICATOR';

export type GraphEdgeType =
  | 'CONTAINS_URL' | 'HAS_ATTACHMENT' | 'RECEIVED_FROM_IP' | 'BELONGS_TO_DOMAIN'
  | 'HAS_HASH' | 'CONTAINS_QR' | 'DECODED_TO_URL' | 'IS_APK'
  | 'OBSERVED_BY_CTI' | 'HAS_GEOLOCATION' | 'HAS_INDICATOR';

export interface ProvenanceEntry {
  source: string;
  sourceRecordId?: string;
  confidence?: number | null;
  createdAt?: string;
}

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  organizationId: string;
  data: Record<string, unknown>;
  provenance: ProvenanceEntry[];
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  type: GraphEdgeType;
  provenance: ProvenanceEntry[];
}

export interface EvidenceGraph {
  emailId: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  metadata: {
    generatedAt: string;
    nodeCount: number;
    edgeCount: number;
    truncated: boolean;
  };
}

// Bounds the graph so one pathological email (thousands of URLs/attachments)
// can never produce an unbounded response. Truncation is reported, not silent.
const MAX_NODES = 500;
const MAX_EDGES = 1000;

// ---- Deterministic node identity (Step 6) ----
const nodeId = {
  email: (emailId: string) => `EMAIL:${emailId}`,
  url: (normalizedOrRaw: string) => `URL:${normalizedOrRaw.toLowerCase()}`,
  domain: (domain: string) => `DOMAIN:${domain.toLowerCase()}`,
  ip: (ip: string) => `IP:${ip}`,
  attachment: (attachmentId: string) => `ATTACHMENT:${attachmentId}`,
  hash: (sha256: string) => `HASH:${sha256.toLowerCase()}`,
  qr: (attachmentId: string, index: number) => `QR:${attachmentId}:${index}`,
  apk: (attachmentId: string) => `APK:${attachmentId}`,
  cti: (indicatorValue: string) => `CTI:${indicatorValue.toLowerCase()}`,
  geo: (ip: string) => `GEO:${ip}`,
  threatIndicator: (category: string) => `THREAT_INDICATOR:${category}`,
};

class GraphBuilder {
  private nodes = new Map<string, GraphNode>();
  private edges = new Map<string, GraphEdge>();
  private nodeLimitHit = false;
  private edgeLimitHit = false;

  constructor(private readonly organizationId: string) {}

  addNode(id: string, type: GraphNodeType, label: string, data: Record<string, unknown>, provenance: ProvenanceEntry): void {
    const existing = this.nodes.get(id);
    if (existing) {
      if (!this.hasSameProvenance(existing.provenance, provenance)) {
        existing.provenance.push(provenance);
      }
      return;
    }
    if (this.nodes.size >= MAX_NODES) {
      this.nodeLimitHit = true;
      return;
    }
    this.nodes.set(id, { id, type, label, organizationId: this.organizationId, data, provenance: [provenance] });
  }

  addEdge(from: string, to: string, type: GraphEdgeType, provenance: ProvenanceEntry): void {
    // Never link a node that was dropped due to the node cap — an edge to a
    // non-existent node would be a broken/misleading graph, not a bounded one.
    if (!this.nodes.has(from) || !this.nodes.has(to)) return;

    const id = `${from}|${type}|${to}`;
    const existing = this.edges.get(id);
    if (existing) {
      if (!this.hasSameProvenance(existing.provenance, provenance)) {
        existing.provenance.push(provenance);
      }
      return;
    }
    if (this.edges.size >= MAX_EDGES) {
      this.edgeLimitHit = true;
      return;
    }
    this.edges.set(id, { id, from, to, type, provenance: [provenance] });
  }

  private hasSameProvenance(list: ProvenanceEntry[], entry: ProvenanceEntry): boolean {
    return list.some((p) => p.source === entry.source && p.sourceRecordId === entry.sourceRecordId);
  }

  build(emailId: string): EvidenceGraph {
    // Sorted by ID for deterministic output ordering (Step 14: repeated
    // generation must produce the same logical — here, byte-identical —
    // result for the same input).
    const nodes = Array.from(this.nodes.values()).sort((a, b) => a.id.localeCompare(b.id));
    const edges = Array.from(this.edges.values()).sort((a, b) => a.id.localeCompare(b.id));

    return {
      emailId,
      nodes,
      edges,
      metadata: {
        generatedAt: new Date().toISOString(),
        nodeCount: nodes.length,
        edgeCount: edges.length,
        truncated: this.nodeLimitHit || this.edgeLimitHit,
      },
    };
  }
}

// ---- Input shapes (exactly what the route already fetches — no new queries) ----

export interface EvidenceGraphInput {
  emailId: string;
  organizationId: string;
  senderAddress: string | null;
  relayHops: Array<{ sourceIp: string | null; hopOrder: number; receivedHeader: string }>;
  urls: Array<{
    id: string;
    url: string;
    normalizedUrl: string | null;
    domain: string | null;
    source: string;
    indicators: unknown;
  }>;
  attachments: Array<{
    id: string;
    filename: string;
    sha256: string | null;
    apkMetadata: unknown;
    qrFindings: unknown;
    threatIndicators: unknown;
  }>;
  geoLocations: Array<{ ipAddress: string; country: string | null; city: string | null; asn: string | null; isp: string | null; provider: string }>;
  indicatorObservations: Array<{ value: string; type: string; verdict: string; confidence: number | null; provider: string; observationTime: Date }>;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function asIndicatorEntries(value: unknown): Array<{ category: string; severity?: string; description?: string }> {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is { category: string } => !!v && typeof v === 'object' && typeof (v as { category?: unknown }).category === 'string');
}

/** Builds the evidence graph for one email from already-fetched, already-
 *  persisted rows. Never calls a database or an external provider itself. */
export function buildEvidenceGraph(input: EvidenceGraphInput): EvidenceGraph {
  const g = new GraphBuilder(input.organizationId);
  const emailNodeId = nodeId.email(input.emailId);

  g.addNode(emailNodeId, 'EMAIL', input.senderAddress ?? input.emailId, { emailId: input.emailId }, {
    source: 'EMAIL_RECORD',
    sourceRecordId: input.emailId,
  });

  // --- Relay IPs ---
  const geoByIp = new Map(input.geoLocations.map((g2) => [g2.ipAddress, g2]));
  const indicatorByValue = new Map(input.indicatorObservations.map((o) => [o.value.toLowerCase(), o]));

  for (const hop of input.relayHops) {
    if (!hop.sourceIp) continue;
    const ipId = nodeId.ip(hop.sourceIp);
    g.addNode(ipId, 'IP', hop.sourceIp, { ip: hop.sourceIp, hopOrder: hop.hopOrder }, {
      source: 'RECEIVED_HEADER',
      sourceRecordId: String(hop.hopOrder),
    });
    g.addEdge(emailNodeId, ipId, 'RECEIVED_FROM_IP', { source: 'RECEIVED_HEADER', sourceRecordId: String(hop.hopOrder) });

    const geo = geoByIp.get(hop.sourceIp);
    if (geo) {
      const geoId = nodeId.geo(hop.sourceIp);
      g.addNode(geoId, 'GEOLOCATION', `${geo.city ?? '?'}, ${geo.country ?? '?'}`, { ...geo }, {
        source: 'CTI_PROVIDER',
        sourceRecordId: geo.provider,
      });
      g.addEdge(ipId, geoId, 'HAS_GEOLOCATION', { source: 'CTI_PROVIDER', sourceRecordId: geo.provider });
    }

    const obs = indicatorByValue.get(hop.sourceIp.toLowerCase());
    if (obs) {
      const ctiId = nodeId.cti(obs.value);
      g.addNode(ctiId, 'CTI_INDICATOR', `${obs.verdict} (${obs.provider})`, { verdict: obs.verdict, confidence: obs.confidence, provider: obs.provider }, {
        source: 'CTI_PROVIDER',
        sourceRecordId: obs.provider,
        confidence: obs.confidence,
        createdAt: obs.observationTime.toISOString(),
      });
      g.addEdge(ipId, ctiId, 'OBSERVED_BY_CTI', { source: 'CTI_PROVIDER', sourceRecordId: obs.provider });
    }
  }

  // --- URLs / domains / URL-level threat indicators ---
  // Track which URL strings came from a QR code so the QR_CODE → URL edge
  // below can be attached without a second, invented extraction pass.
  const qrUrlPayloads = new Set<string>();

  for (const url of input.urls) {
    const urlId = nodeId.url(url.normalizedUrl ?? url.url);
    g.addNode(urlId, 'URL', url.url, { url: url.url, normalizedUrl: url.normalizedUrl }, {
      source: url.source,
      sourceRecordId: url.id,
    });
    g.addEdge(emailNodeId, urlId, 'CONTAINS_URL', { source: url.source, sourceRecordId: url.id });

    if (url.source === 'QR_CODE') qrUrlPayloads.add(url.url);

    if (url.domain) {
      const domainId = nodeId.domain(url.domain);
      g.addNode(domainId, 'DOMAIN', url.domain, { domain: url.domain }, { source: url.source, sourceRecordId: url.id });
      g.addEdge(urlId, domainId, 'BELONGS_TO_DOMAIN', { source: url.source, sourceRecordId: url.id });

      const obs = indicatorByValue.get(url.domain.toLowerCase());
      if (obs) {
        const ctiId = nodeId.cti(obs.value);
        g.addNode(ctiId, 'CTI_INDICATOR', `${obs.verdict} (${obs.provider})`, { verdict: obs.verdict, confidence: obs.confidence, provider: obs.provider }, {
          source: 'CTI_PROVIDER',
          sourceRecordId: obs.provider,
          confidence: obs.confidence,
          createdAt: obs.observationTime.toISOString(),
        });
        g.addEdge(domainId, ctiId, 'OBSERVED_BY_CTI', { source: 'CTI_PROVIDER', sourceRecordId: obs.provider });
      }
    }

    // EmailUrl.indicators is a plain string[] (e.g. "BRAND_IMPERSONATION_SUBDOMAIN"),
    // unlike EmailAttachment.threatIndicators which is an array of richer objects.
    for (const category of asStringArray(url.indicators)) {
      const tiId = nodeId.threatIndicator(category);
      g.addNode(tiId, 'THREAT_INDICATOR', category, { category }, {
        source: 'URL_ANALYSIS',
        sourceRecordId: url.id,
      });
      g.addEdge(urlId, tiId, 'HAS_INDICATOR', { source: 'URL_ANALYSIS', sourceRecordId: url.id });
    }
  }

  // --- Attachments / hashes / APK / QR / attachment-level indicators ---
  for (const att of input.attachments) {
    const attId = nodeId.attachment(att.id);
    g.addNode(attId, 'ATTACHMENT', att.filename, { filename: att.filename }, { source: 'ATTACHMENT', sourceRecordId: att.id });
    g.addEdge(emailNodeId, attId, 'HAS_ATTACHMENT', { source: 'ATTACHMENT', sourceRecordId: att.id });

    if (att.sha256) {
      const hashId = nodeId.hash(att.sha256);
      g.addNode(hashId, 'FILE_HASH', att.sha256, { sha256: att.sha256 }, { source: 'ATTACHMENT', sourceRecordId: att.id });
      g.addEdge(attId, hashId, 'HAS_HASH', { source: 'ATTACHMENT', sourceRecordId: att.id });

      const obs = indicatorByValue.get(att.sha256.toLowerCase());
      if (obs) {
        const ctiId = nodeId.cti(obs.value);
        g.addNode(ctiId, 'CTI_INDICATOR', `${obs.verdict} (${obs.provider})`, { verdict: obs.verdict, confidence: obs.confidence, provider: obs.provider }, {
          source: 'CTI_PROVIDER',
          sourceRecordId: obs.provider,
          confidence: obs.confidence,
          createdAt: obs.observationTime.toISOString(),
        });
        g.addEdge(hashId, ctiId, 'OBSERVED_BY_CTI', { source: 'CTI_PROVIDER', sourceRecordId: obs.provider });
      }
    }

    if (att.apkMetadata && typeof att.apkMetadata === 'object') {
      const apkId = nodeId.apk(att.id);
      const apk = att.apkMetadata as { packageName?: string | null };
      g.addNode(apkId, 'APK', apk.packageName ?? att.filename, { ...(att.apkMetadata as object) }, { source: 'ATTACHMENT', sourceRecordId: att.id });
      g.addEdge(attId, apkId, 'IS_APK', { source: 'ATTACHMENT', sourceRecordId: att.id });
    }

    if (att.qrFindings && typeof att.qrFindings === 'object') {
      const qr = att.qrFindings as { codes?: Array<{ payload: string; type: string }> };
      (qr.codes ?? []).forEach((code, index) => {
        const qrId = nodeId.qr(att.id, index);
        g.addNode(qrId, 'QR_CODE', code.payload.slice(0, 80), { payload: code.payload, type: code.type }, { source: 'QR_CODE', sourceRecordId: att.id });
        g.addEdge(attId, qrId, 'CONTAINS_QR', { source: 'QR_CODE', sourceRecordId: att.id });

        // Only link to a real, already-persisted URL node — never fabricate
        // a URL node here even if the payload looks like one.
        if (code.type === 'URL' && qrUrlPayloads.has(code.payload)) {
          const urlId = nodeId.url(code.payload);
          if (input.urls.some((u) => nodeId.url(u.normalizedUrl ?? u.url) === urlId)) {
            g.addEdge(qrId, urlId, 'DECODED_TO_URL', { source: 'QR_CODE', sourceRecordId: att.id });
          }
        }
      });
    }

    for (const entry of asIndicatorEntries(att.threatIndicators)) {
      const tiId = nodeId.threatIndicator(entry.category);
      g.addNode(tiId, 'THREAT_INDICATOR', entry.category, { category: entry.category, description: entry.description }, {
        source: 'ATTACHMENT_ANALYSIS',
        sourceRecordId: att.id,
      });
      g.addEdge(attId, tiId, 'HAS_INDICATOR', { source: 'ATTACHMENT_ANALYSIS', sourceRecordId: att.id });
    }
  }

  return g.build(input.emailId);
}
