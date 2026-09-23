/**
 * Deterministic Evidence Graph builder.
 *
 * Extended for Phase J (SENDER/RECIPIENT/CASE/EVIDENCE/ALERT nodes,
 * EMAIL_SENT_FROM/EMAIL_SENT_TO/BELONGS_TO_CASE/EMAIL_GENERATED_EVIDENCE/
 * EVIDENCE_SUPPORTS_FINDING/HAS_ALERT edges). Deliberately NOT implemented:
 * a DOMAIN_RESOLVES_TO_IP edge — no A-record/DNS-resolution capability
 * exists anywhere in this pipeline (DnsResolver only performs TXT/MX
 * lookups for SPF/DKIM/DMARC and MX-based SPF mechanisms; see
 * services/worker/src/verifier/DnsResolver.ts), so persisting that edge
 * would mean inventing a domain→IP fact this system never actually
 * observed. Adding it later requires a real A-record lookup step first.
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

import psl from 'psl';

export type GraphNodeType =
  | 'EMAIL' | 'DOMAIN' | 'URL' | 'IP' | 'ATTACHMENT' | 'FILE_HASH'
  | 'QR_CODE' | 'APK' | 'CTI_INDICATOR' | 'GEOLOCATION' | 'THREAT_INDICATOR'
  | 'SENDER' | 'RECIPIENT' | 'EVIDENCE' | 'ALERT' | 'CASE';

export type GraphEdgeType =
  | 'CONTAINS_URL' | 'HAS_ATTACHMENT' | 'RECEIVED_FROM_IP' | 'BELONGS_TO_DOMAIN'
  | 'HAS_HASH' | 'CONTAINS_QR' | 'DECODED_TO_URL' | 'IS_APK'
  | 'OBSERVED_BY_CTI' | 'HAS_GEOLOCATION' | 'HAS_INDICATOR'
  | 'EMAIL_SENT_FROM' | 'EMAIL_SENT_TO' | 'BELONGS_TO_CASE'
  | 'EMAIL_GENERATED_EVIDENCE' | 'EVIDENCE_SUPPORTS_FINDING' | 'HAS_ALERT';

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
  sender: (address: string) => `SENDER:${address.toLowerCase()}`,
  recipient: (address: string) => `RECIPIENT:${address.toLowerCase()}`,
  case: (caseId: string) => `CASE:${caseId}`,
  evidence: (evidenceId: string) => `EVIDENCE:${evidenceId}`,
  alert: (alertId: string) => `ALERT:${alertId}`,
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
  // Phase N — most-recent PTR observation per relay IP, keyed by IP
  // (DnsObservation.queryName). hostnames is null when no PTR record exists
  // or the lookup failed; attacker-influenceable, never a verified identity.
  reverseDnsObservations: Array<{ ipAddress: string; hostnames: string[] | null }>;
  indicatorObservations: Array<{ value: string; type: string; verdict: string; confidence: number | null; provider: string; observationTime: Date }>;
  // Phase L — keyed by registrable domain (what RDAP resolves), attached to
  // the matching DOMAIN node's `data` when a URL's domain reduces to it.
  domainIntelligence: Array<{
    registrableDomain: string;
    status: string;
    registrar: string | null;
    registrationDate: Date | null;
    expirationDate: Date | null;
    nameservers: unknown;
    domainStatus: unknown;
  }>;
  recipients: Array<{ headerName: string; address: string | null }>;
  // Present only when this email is linked to a Case (Email.caseId) — the
  // graph never invents a case relationship for an unlinked email.
  caseContext: {
    caseId: string;
    title: string;
    status: string;
    priority: string;
    // Evidence/alerts belonging to the same case as this email — a real,
    // already-persisted relationship (both are case-scoped), not a
    // fabricated "this email produced this evidence" claim. Provenance on
    // each edge makes this scoping explicit.
    // Phase M — anchorStatus/merkleRoot are read directly from the
    // Evidence/BlockchainAnchor rows (via a join in the route), never
    // recomputed here — the dedicated GET /evidence/:id/integrity endpoint
    // is the one place that does real hash/chain/Merkle verification, so
    // the graph only surfaces already-persisted status, avoiding two
    // inconsistent sources of integrity truth.
    evidence: Array<{ id: string; type: string; sha256: string | null; filename: string | null; collectionTime: Date; anchorStatus: string | null; merkleRoot: string | null }>;
    alerts: Array<{ id: string; title: string; severity: string; createdAt: Date }>;
  } | null;
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
  const domainIntelByRegistrable = new Map(input.domainIntelligence.map((d) => [d.registrableDomain, d]));

  g.addNode(emailNodeId, 'EMAIL', input.senderAddress ?? input.emailId, { emailId: input.emailId }, {
    source: 'EMAIL_RECORD',
    sourceRecordId: input.emailId,
  });

  // --- Sender / recipients ---
  if (input.senderAddress) {
    const senderId = nodeId.sender(input.senderAddress);
    g.addNode(senderId, 'SENDER', input.senderAddress, { address: input.senderAddress }, {
      source: 'EMAIL_RECORD',
      sourceRecordId: input.emailId,
    });
    g.addEdge(emailNodeId, senderId, 'EMAIL_SENT_FROM', { source: 'EMAIL_RECORD', sourceRecordId: input.emailId });
  }

  for (const recipient of input.recipients) {
    if (!recipient.address) continue;
    const recipientId = nodeId.recipient(recipient.address);
    g.addNode(recipientId, 'RECIPIENT', recipient.address, { address: recipient.address, headerName: recipient.headerName }, {
      source: 'EMAIL_RECORD',
      sourceRecordId: input.emailId,
    });
    g.addEdge(emailNodeId, recipientId, 'EMAIL_SENT_TO', { source: 'EMAIL_RECORD', sourceRecordId: input.emailId });
  }

  // --- Relay IPs ---
  const geoByIp = new Map(input.geoLocations.map((g2) => [g2.ipAddress, g2]));
  const indicatorByValue = new Map(input.indicatorObservations.map((o) => [o.value.toLowerCase(), o]));
  const reverseDnsByIp = new Map(input.reverseDnsObservations.map((r) => [r.ipAddress, r.hostnames]));

  for (const hop of input.relayHops) {
    if (!hop.sourceIp) continue;
    const ipId = nodeId.ip(hop.sourceIp);
    g.addNode(ipId, 'IP', hop.sourceIp, { ip: hop.sourceIp, hopOrder: hop.hopOrder, reverseDns: reverseDnsByIp.get(hop.sourceIp) ?? null }, {
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
      const registrable = psl.get(url.domain.toLowerCase());
      const intel = registrable ? domainIntelByRegistrable.get(registrable) : undefined;
      g.addNode(domainId, 'DOMAIN', url.domain, {
        domain: url.domain,
        // Honest RDAP fields — only present when a real lookup has
        // actually happened (see DomainIntelligence.status); never
        // fabricated for a domain that hasn't been enriched yet.
        domainIntelligence: intel
          ? {
              status: intel.status,
              registrar: intel.registrar,
              registrationDate: intel.registrationDate,
              expirationDate: intel.expirationDate,
              nameservers: intel.nameservers,
              domainStatus: intel.domainStatus,
            }
          : null,
      }, { source: url.source, sourceRecordId: url.id });
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

  // --- Case / Evidence / Alerts (only when this email is linked to a case —
  // never fabricated for an unlinked email) ---
  if (input.caseContext) {
    const { caseId, title, status, priority, evidence, alerts } = input.caseContext;
    const caseNodeId = nodeId.case(caseId);
    g.addNode(caseNodeId, 'CASE', title, { caseId, status, priority }, {
      source: 'CASE_RECORD',
      sourceRecordId: caseId,
    });
    g.addEdge(emailNodeId, caseNodeId, 'BELONGS_TO_CASE', { source: 'CASE_RECORD', sourceRecordId: caseId });

    for (const ev of evidence) {
      const evidenceNodeId = nodeId.evidence(ev.id);
      g.addNode(evidenceNodeId, 'EVIDENCE', ev.filename ?? ev.type, {
        evidenceType: ev.type,
        filename: ev.filename,
        // 'NOT_BATCHED' is an honest, explicit state — never omitted or
        // fabricated as any of the real BlockchainAnchorStatus values.
        anchorStatus: ev.anchorStatus ?? 'NOT_BATCHED',
        merkleRoot: ev.merkleRoot,
      }, {
        source: 'CASE_EVIDENCE',
        sourceRecordId: ev.id,
        createdAt: ev.collectionTime.toISOString(),
      });
      // Case-scoped, not email-scoped: this evidence belongs to the same
      // case as this email, which is the real relationship we can attest to
      // — never claimed to have been literally extracted from this email.
      g.addEdge(caseNodeId, evidenceNodeId, 'EMAIL_GENERATED_EVIDENCE', { source: 'CASE_EVIDENCE', sourceRecordId: ev.id });

      // Only when the evidence's own SHA-256 genuinely matches an
      // already-persisted FILE_HASH node from this email's attachments —
      // a real, verifiable link, never inferred from anything else.
      if (ev.sha256) {
        const hashId = nodeId.hash(ev.sha256);
        if (input.attachments.some((a) => a.sha256 && nodeId.hash(a.sha256) === hashId)) {
          g.addEdge(evidenceNodeId, hashId, 'EVIDENCE_SUPPORTS_FINDING', { source: 'CASE_EVIDENCE', sourceRecordId: ev.id });
        }
      }
    }

    for (const alert of alerts) {
      const alertNodeId = nodeId.alert(alert.id);
      g.addNode(alertNodeId, 'ALERT', alert.title, { severity: alert.severity }, {
        source: 'CASE_ALERT',
        sourceRecordId: alert.id,
        createdAt: alert.createdAt.toISOString(),
      });
      g.addEdge(caseNodeId, alertNodeId, 'HAS_ALERT', { source: 'CASE_ALERT', sourceRecordId: alert.id });
    }
  }

  return g.build(input.emailId);
}
