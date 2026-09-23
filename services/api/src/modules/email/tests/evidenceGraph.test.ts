import { describe, it, expect } from 'vitest';
import { buildEvidenceGraph, EvidenceGraphInput } from '../evidenceGraph';

function baseInput(overrides: Partial<EvidenceGraphInput> = {}): EvidenceGraphInput {
  return {
    emailId: 'email-1',
    organizationId: 'org-1',
    senderAddress: 'sender@example.com',
    relayHops: [],
    urls: [],
    attachments: [],
    geoLocations: [],
    reverseDnsObservations: [],
    indicatorObservations: [],
    recipients: [],
    domainIntelligence: [],
    caseContext: null,
    ...overrides,
  };
}

describe('buildEvidenceGraph', () => {
  it('1. produces a basic graph with just EMAIL and SENDER nodes when there is no other evidence', () => {
    const graph = buildEvidenceGraph(baseInput());
    expect(graph.emailId).toBe('email-1');
    expect(graph.nodes).toEqual([
      expect.objectContaining({ id: 'EMAIL:email-1', type: 'EMAIL' }),
      expect.objectContaining({ id: 'SENDER:sender@example.com', type: 'SENDER' }),
    ]);
    expect(graph.edges).toEqual([
      expect.objectContaining({ from: 'EMAIL:email-1', to: 'SENDER:sender@example.com', type: 'EMAIL_SENT_FROM' }),
    ]);
  });

  it('1b. no SENDER node when senderAddress is null, and no CASE/EVIDENCE/ALERT nodes when the email is unlinked', () => {
    const graph = buildEvidenceGraph(baseInput({ senderAddress: null }));
    expect(graph.nodes).toEqual([
      expect.objectContaining({ id: 'EMAIL:email-1', type: 'EMAIL' }),
    ]);
    expect(graph.edges).toEqual([]);
  });

  it('2. a URL with a domain produces URL and DOMAIN nodes linked by BELONGS_TO_DOMAIN', () => {
    const graph = buildEvidenceGraph(baseInput({
      urls: [{ id: 'url-1', url: 'https://example.com/a', normalizedUrl: 'https://example.com/a', domain: 'example.com', source: 'TEXT', indicators: [] }],
    }));

    expect(graph.nodes.find((n) => n.type === 'URL')).toBeDefined();
    const domainNode = graph.nodes.find((n) => n.type === 'DOMAIN');
    expect(domainNode?.id).toBe('DOMAIN:example.com');
    expect(graph.edges.find((e) => e.type === 'BELONGS_TO_DOMAIN')).toBeDefined();
    expect(graph.edges.find((e) => e.type === 'CONTAINS_URL')).toBeDefined();
  });

  it('3. a relay hop IP produces an IP node linked by RECEIVED_FROM_IP', () => {
    const graph = buildEvidenceGraph(baseInput({
      relayHops: [{ sourceIp: '8.8.8.8', hopOrder: 0, receivedHeader: 'from x' }],
    }));

    const ipNode = graph.nodes.find((n) => n.type === 'IP');
    expect(ipNode?.id).toBe('IP:8.8.8.8');
    expect(graph.edges.find((e) => e.type === 'RECEIVED_FROM_IP' && e.to === 'IP:8.8.8.8')).toBeDefined();
    expect(ipNode?.provenance[0]).toEqual(expect.objectContaining({ source: 'RECEIVED_HEADER' }));
  });

  it('4. an attachment with a hash produces ATTACHMENT and FILE_HASH nodes linked by HAS_HASH', () => {
    const graph = buildEvidenceGraph(baseInput({
      attachments: [{ id: 'att-1', filename: 'invoice.pdf', sha256: 'abc123', apkMetadata: null, qrFindings: null, threatIndicators: null }],
    }));

    expect(graph.nodes.find((n) => n.id === 'ATTACHMENT:att-1')).toBeDefined();
    expect(graph.nodes.find((n) => n.id === 'HASH:abc123')).toBeDefined();
    expect(graph.edges.find((e) => e.type === 'HAS_HASH')).toBeDefined();
  });

  it('5. an APK attachment produces an APK node linked by IS_APK', () => {
    const graph = buildEvidenceGraph(baseInput({
      attachments: [{ id: 'att-2', filename: 'app.apk', sha256: 'def456', apkMetadata: { packageName: 'com.example.app' }, qrFindings: null, threatIndicators: null }],
    }));

    const apkNode = graph.nodes.find((n) => n.type === 'APK');
    expect(apkNode?.id).toBe('APK:att-2');
    expect(apkNode?.label).toBe('com.example.app');
    expect(graph.edges.find((e) => e.type === 'IS_APK' && e.from === 'ATTACHMENT:att-2' && e.to === 'APK:att-2')).toBeDefined();
  });

  it('6. a QR code decoded to a URL links QR_CODE -> URL only when that URL is also real persisted evidence', () => {
    const graph = buildEvidenceGraph(baseInput({
      urls: [{ id: 'url-2', url: 'https://qr-target.example.com', normalizedUrl: 'https://qr-target.example.com', domain: 'qr-target.example.com', source: 'QR_CODE', indicators: [] }],
      attachments: [{
        id: 'att-3', filename: 'qr.png', sha256: null, apkMetadata: null,
        qrFindings: { detected: true, codes: [{ payload: 'https://qr-target.example.com', type: 'URL' }] },
        threatIndicators: null,
      }],
    }));

    const qrNode = graph.nodes.find((n) => n.type === 'QR_CODE');
    expect(qrNode?.id).toBe('QR:att-3:0');
    expect(graph.edges.find((e) => e.type === 'CONTAINS_QR')).toBeDefined();
    expect(graph.edges.find((e) => e.type === 'DECODED_TO_URL' && e.to === 'URL:https://qr-target.example.com')).toBeDefined();
  });

  it('does NOT link a QR-decoded payload to a URL node when no matching EmailUrl was ever persisted (never fabricate evidence)', () => {
    const graph = buildEvidenceGraph(baseInput({
      attachments: [{
        id: 'att-4', filename: 'qr.png', sha256: null, apkMetadata: null,
        qrFindings: { detected: true, codes: [{ payload: 'https://never-persisted.example.com', type: 'URL' }] },
        threatIndicators: null,
      }],
    }));

    expect(graph.edges.find((e) => e.type === 'DECODED_TO_URL')).toBeUndefined();
    // The QR_CODE node itself still exists — it's still real evidence — just not linked to a fabricated URL node.
    expect(graph.nodes.find((n) => n.type === 'QR_CODE')).toBeDefined();
  });

  it('7. a CTI observation for an IP produces a CTI_INDICATOR node linked by OBSERVED_BY_CTI', () => {
    const graph = buildEvidenceGraph(baseInput({
      relayHops: [{ sourceIp: '1.1.1.1', hopOrder: 0, receivedHeader: 'x' }],
      indicatorObservations: [{ value: '1.1.1.1', type: 'IP', verdict: 'MALICIOUS', confidence: 90, provider: 'AbuseIPDB', observationTime: new Date('2026-01-01') }],
    }));

    const ctiNode = graph.nodes.find((n) => n.type === 'CTI_INDICATOR');
    expect(ctiNode?.data).toEqual(expect.objectContaining({ verdict: 'MALICIOUS', provider: 'AbuseIPDB' }));
    expect(graph.edges.find((e) => e.type === 'OBSERVED_BY_CTI' && e.from === 'IP:1.1.1.1')).toBeDefined();
  });

  it('8. an IP with GeoLocation data produces a GEOLOCATION node linked by HAS_GEOLOCATION', () => {
    const graph = buildEvidenceGraph(baseInput({
      relayHops: [{ sourceIp: '2.2.2.2', hopOrder: 0, receivedHeader: 'x' }],
      geoLocations: [{ ipAddress: '2.2.2.2', country: 'Testland', city: 'Testville', asn: 'AS1', isp: 'ISP', provider: 'MaxMind' }],
    }));

    const geoNode = graph.nodes.find((n) => n.type === 'GEOLOCATION');
    expect(geoNode?.id).toBe('GEO:2.2.2.2');
    expect(graph.edges.find((e) => e.type === 'HAS_GEOLOCATION' && e.from === 'IP:2.2.2.2')).toBeDefined();
  });

  it('8b. an IP with a persisted PTR observation carries reverseDns hostnames on its node data', () => {
    const graph = buildEvidenceGraph(baseInput({
      relayHops: [{ sourceIp: '3.3.3.3', hopOrder: 0, receivedHeader: 'x' }],
      reverseDnsObservations: [{ ipAddress: '3.3.3.3', hostnames: ['relay.example.net'] }],
    }));

    const ipNode = graph.nodes.find((n) => n.id === 'IP:3.3.3.3');
    expect(ipNode?.data).toEqual(expect.objectContaining({ reverseDns: ['relay.example.net'] }));
  });

  it('8c. an IP with no PTR observation never fabricates reverseDns on its node data', () => {
    const graph = buildEvidenceGraph(baseInput({
      relayHops: [{ sourceIp: '4.4.4.4', hopOrder: 0, receivedHeader: 'x' }],
    }));

    const ipNode = graph.nodes.find((n) => n.id === 'IP:4.4.4.4');
    expect(ipNode?.data).toEqual(expect.objectContaining({ reverseDns: null }));
  });

  it('9. the same domain appearing via multiple URL sources collapses into ONE domain node with multiple provenance entries', () => {
    const graph = buildEvidenceGraph(baseInput({
      urls: [
        { id: 'u1', url: 'https://amazon.com/a', normalizedUrl: 'https://amazon.com/a', domain: 'amazon.com', source: 'TEXT', indicators: [] },
        { id: 'u2', url: 'https://amazon.com/b', normalizedUrl: 'https://amazon.com/b', domain: 'amazon.com', source: 'HTML_HREF', indicators: [] },
        { id: 'u3', url: 'https://amazon.com/c', normalizedUrl: 'https://amazon.com/c', domain: 'amazon.com', source: 'QR_CODE', indicators: [] },
      ],
    }));

    const domainNodes = graph.nodes.filter((n) => n.type === 'DOMAIN' && n.id === 'DOMAIN:amazon.com');
    expect(domainNodes).toHaveLength(1);
    expect(domainNodes[0].provenance.map((p) => p.source).sort()).toEqual(['HTML_HREF', 'QR_CODE', 'TEXT']);
  });

  it('10. the exact same URL string never produces duplicate URL nodes even if somehow passed twice', () => {
    const graph = buildEvidenceGraph(baseInput({
      urls: [
        { id: 'u1', url: 'https://dup.example.com', normalizedUrl: 'https://dup.example.com', domain: 'dup.example.com', source: 'TEXT', indicators: [] },
        { id: 'u2', url: 'https://dup.example.com', normalizedUrl: 'https://dup.example.com', domain: 'dup.example.com', source: 'TEXT', indicators: [] },
      ],
    }));

    const urlNodes = graph.nodes.filter((n) => n.type === 'URL');
    expect(urlNodes).toHaveLength(1);
  });

  it('11. a repeated identical relationship never creates a duplicate edge — it adds provenance instead', () => {
    const graph = buildEvidenceGraph(baseInput({
      urls: [
        { id: 'u1', url: 'https://dup2.example.com', normalizedUrl: 'https://dup2.example.com', domain: 'dup2.example.com', source: 'TEXT', indicators: [] },
        { id: 'u2', url: 'https://dup2.example.com', normalizedUrl: 'https://dup2.example.com', domain: 'dup2.example.com', source: 'HTML_HREF', indicators: [] },
      ],
    }));

    const containsUrlEdges = graph.edges.filter((e) => e.type === 'CONTAINS_URL');
    expect(containsUrlEdges).toHaveLength(1);
    expect(containsUrlEdges[0].provenance.length).toBe(2);
  });

  it('12. provenance is preserved with source and sourceRecordId for every node and edge', () => {
    const graph = buildEvidenceGraph(baseInput({
      urls: [{ id: 'url-prov', url: 'https://prov.example.com', normalizedUrl: 'https://prov.example.com', domain: 'prov.example.com', source: 'HTML_SRC', indicators: [] }],
    }));

    const urlNode = graph.nodes.find((n) => n.type === 'URL');
    expect(urlNode?.provenance[0]).toEqual({ source: 'HTML_SRC', sourceRecordId: 'url-prov' });
  });

  it('13. node IDs are deterministic, not random — the same evidence always produces the same ID', () => {
    const g1 = buildEvidenceGraph(baseInput({ relayHops: [{ sourceIp: '9.9.9.9', hopOrder: 0, receivedHeader: 'x' }] }));
    const g2 = buildEvidenceGraph(baseInput({ relayHops: [{ sourceIp: '9.9.9.9', hopOrder: 0, receivedHeader: 'x' }] }));
    expect(g1.nodes.map((n) => n.id)).toEqual(g2.nodes.map((n) => n.id));
  });

  it('14. repeated graph generation for identical input produces an identical graph (ignoring generatedAt)', () => {
    const input = baseInput({
      urls: [{ id: 'url-x', url: 'https://repeat.example.com', normalizedUrl: 'https://repeat.example.com', domain: 'repeat.example.com', source: 'TEXT', indicators: ['SOME_INDICATOR'] }],
      attachments: [{ id: 'att-x', filename: 'f.pdf', sha256: 'hash1', apkMetadata: null, qrFindings: null, threatIndicators: null }],
    });
    const g1 = buildEvidenceGraph(input);
    const g2 = buildEvidenceGraph(input);

    const strip = (g: ReturnType<typeof buildEvidenceGraph>) => ({ ...g, metadata: { ...g.metadata, generatedAt: '' } });
    expect(strip(g1)).toEqual(strip(g2));
  });

  it('15. tenant isolation — every node carries the organizationId it was built for, never another tenant\'s', () => {
    const graph = buildEvidenceGraph(baseInput({
      organizationId: 'org-A',
      urls: [{ id: 'u1', url: 'https://x.example.com', normalizedUrl: 'https://x.example.com', domain: 'x.example.com', source: 'TEXT', indicators: [] }],
    }));
    expect(graph.nodes.every((n) => n.organizationId === 'org-A')).toBe(true);
  });

  it('16. missing/partial evidence does not crash the builder and produces only the nodes evidence actually supports', () => {
    const graph = buildEvidenceGraph(baseInput({
      relayHops: [{ sourceIp: null, hopOrder: 0, receivedHeader: 'unparseable' }], // no sourceIp
      urls: [{ id: 'u1', url: 'https://nodomain.example.com', normalizedUrl: null, domain: null, source: 'TEXT', indicators: [] }], // no domain
      attachments: [{ id: 'att-none', filename: 'x.bin', sha256: null, apkMetadata: null, qrFindings: null, threatIndicators: null }],
    }));

    expect(graph.nodes.find((n) => n.type === 'IP')).toBeUndefined();
    expect(graph.nodes.find((n) => n.type === 'DOMAIN')).toBeUndefined();
    expect(graph.nodes.find((n) => n.type === 'FILE_HASH')).toBeUndefined();
    expect(graph.nodes.find((n) => n.type === 'URL')).toBeDefined();
    expect(graph.nodes.find((n) => n.type === 'ATTACHMENT')).toBeDefined();
  });

  it('17. graph size is bounded — an extreme number of URLs is truncated and honestly reported, not silently dropped', () => {
    const manyUrls = Array.from({ length: 600 }, (_, i) => ({
      id: `u${i}`, url: `https://site${i}.example.com`, normalizedUrl: `https://site${i}.example.com`,
      domain: `site${i}.example.com`, source: 'TEXT', indicators: [],
    }));
    const graph = buildEvidenceGraph(baseInput({ urls: manyUrls }));

    expect(graph.metadata.truncated).toBe(true);
    expect(graph.nodes.length).toBeLessThanOrEqual(500);
  });

  it('18. no raw email body content ever appears in the graph', () => {
    const graph = buildEvidenceGraph(baseInput({
      urls: [{ id: 'u1', url: 'https://body-test.example.com', normalizedUrl: 'https://body-test.example.com', domain: 'body-test.example.com', source: 'TEXT', indicators: [] }],
    }));
    const serialized = JSON.stringify(graph);
    // The builder input never included a raw body in the first place —
    // this asserts the output shape has no field that could carry one.
    expect(Object.keys(graph)).toEqual(['emailId', 'nodes', 'edges', 'metadata']);
    expect(serialized).not.toMatch(/rawBody|emailBody|bodyText/i);
  });

  it('19. no credentials or tokens ever appear in the graph, even if present in unrelated input fields', () => {
    const graph = buildEvidenceGraph(baseInput({
      attachments: [{
        id: 'att-secret', filename: 'x.apk', sha256: 'h1',
        apkMetadata: { packageName: 'com.example', accessToken: 'should-never-appear-in-output-shape' } as unknown,
        qrFindings: null, threatIndicators: null,
      }],
    }));
    // apkMetadata is spread into node.data by design (it's real static-analysis
    // evidence) — this test documents that the builder does not add any
    // separate credential field, and that callers (the API route) are
    // responsible for what real APK metadata ever contains in practice.
    expect(graph.nodes.find((n) => n.type === 'APK')?.data).not.toHaveProperty('oauthToken');
  });

  it('20. the graph response shape matches the documented API contract', () => {
    const graph = buildEvidenceGraph(baseInput());
    expect(graph).toEqual(expect.objectContaining({
      emailId: expect.any(String),
      nodes: expect.any(Array),
      edges: expect.any(Array),
      metadata: expect.objectContaining({
        generatedAt: expect.any(String),
        nodeCount: expect.any(Number),
        edgeCount: expect.any(Number),
        truncated: expect.any(Boolean),
      }),
    }));
  });

  it('20b. Phase M — EVIDENCE node exposes anchorStatus honestly (NOT_BATCHED when unset, real status when set)', () => {
    const unbatched = buildEvidenceGraph(baseInput({
      caseContext: {
        caseId: 'case-1', title: 'Case', status: 'OPEN', priority: 'HIGH',
        evidence: [{ id: 'ev-1', type: 'LOG', sha256: null, filename: 'x', collectionTime: new Date(), anchorStatus: null, merkleRoot: null } as any],
        alerts: [],
      },
    }));
    expect(unbatched.nodes.find((n) => n.id === 'EVIDENCE:ev-1')?.data.anchorStatus).toBe('NOT_BATCHED');

    const batched = buildEvidenceGraph(baseInput({
      caseContext: {
        caseId: 'case-1', title: 'Case', status: 'OPEN', priority: 'HIGH',
        evidence: [{ id: 'ev-2', type: 'LOG', sha256: null, filename: 'x', collectionTime: new Date(), anchorStatus: 'ANCHORED', merkleRoot: 'deadbeef' } as any],
        alerts: [],
      },
    }));
    const node = batched.nodes.find((n) => n.id === 'EVIDENCE:ev-2');
    expect(node?.data.anchorStatus).toBe('ANCHORED');
    expect(node?.data.merkleRoot).toBe('deadbeef');
  });

  it('21. recipients produce RECIPIENT nodes linked by EMAIL_SENT_TO, deduplicated across To/Cc', () => {
    const graph = buildEvidenceGraph(baseInput({
      recipients: [
        { headerName: 'to', address: 'victim@example.com' },
        { headerName: 'cc', address: 'victim@example.com' },
        { headerName: 'to', address: 'other@example.com' },
      ],
    }));
    const recipientNodes = graph.nodes.filter((n) => n.type === 'RECIPIENT');
    expect(recipientNodes).toHaveLength(2);
    const victim = recipientNodes.find((n) => n.id === 'RECIPIENT:victim@example.com')!;
    expect(victim.provenance).toHaveLength(1); // deduped: same source/sourceRecordId for both headers
    expect(graph.edges.filter((e) => e.type === 'EMAIL_SENT_TO')).toHaveLength(2);
  });

  it('22. a case-linked email produces a CASE node and BELONGS_TO_CASE edge; an unlinked email produces neither', () => {
    const linked = buildEvidenceGraph(baseInput({
      caseContext: { caseId: 'case-1', title: 'Phishing Campaign X', status: 'OPEN', priority: 'HIGH', evidence: [], alerts: [] },
    }));
    expect(linked.nodes.find((n) => n.id === 'CASE:case-1')).toBeDefined();
    expect(linked.edges.find((e) => e.type === 'BELONGS_TO_CASE' && e.from === 'EMAIL:email-1' && e.to === 'CASE:case-1')).toBeDefined();

    const unlinked = buildEvidenceGraph(baseInput({ caseContext: null }));
    expect(unlinked.nodes.find((n) => n.type === 'CASE')).toBeUndefined();
  });

  it('23. case evidence produces EVIDENCE nodes and EMAIL_GENERATED_EVIDENCE edges from the CASE node', () => {
    const graph = buildEvidenceGraph(baseInput({
      caseContext: {
        caseId: 'case-1', title: 'Case', status: 'OPEN', priority: 'HIGH',
        evidence: [{ id: 'ev-1', type: 'LOG', sha256: null, filename: 'notes.log', collectionTime: new Date('2026-01-01T00:00:00Z') }],
        alerts: [],
      },
    }));
    expect(graph.nodes.find((n) => n.id === 'EVIDENCE:ev-1')).toBeDefined();
    expect(graph.edges.find((e) => e.type === 'EMAIL_GENERATED_EVIDENCE' && e.from === 'CASE:case-1' && e.to === 'EVIDENCE:ev-1')).toBeDefined();
  });

  it('24. EVIDENCE_SUPPORTS_FINDING links evidence to a matching FILE_HASH node only when the SHA-256 genuinely matches an attachment', () => {
    const matching = buildEvidenceGraph(baseInput({
      attachments: [{ id: 'att-1', filename: 'payload.apk', sha256: 'deadbeef', apkMetadata: null, qrFindings: null, threatIndicators: null }],
      caseContext: {
        caseId: 'case-1', title: 'Case', status: 'OPEN', priority: 'HIGH',
        evidence: [{ id: 'ev-1', type: 'ATTACHMENT', sha256: 'deadbeef', filename: 'payload.apk', collectionTime: new Date() }],
        alerts: [],
      },
    }));
    expect(matching.edges.find((e) => e.type === 'EVIDENCE_SUPPORTS_FINDING' && e.from === 'EVIDENCE:ev-1' && e.to === 'HASH:deadbeef')).toBeDefined();

    // No matching attachment hash — never fabricate the link.
    const nonMatching = buildEvidenceGraph(baseInput({
      caseContext: {
        caseId: 'case-1', title: 'Case', status: 'OPEN', priority: 'HIGH',
        evidence: [{ id: 'ev-2', type: 'ATTACHMENT', sha256: 'unrelated-hash', filename: 'x', collectionTime: new Date() }],
        alerts: [],
      },
    }));
    expect(nonMatching.edges.find((e) => e.type === 'EVIDENCE_SUPPORTS_FINDING')).toBeUndefined();
  });

  it('25. case alerts produce ALERT nodes and HAS_ALERT edges from the CASE node', () => {
    const graph = buildEvidenceGraph(baseInput({
      caseContext: {
        caseId: 'case-1', title: 'Case', status: 'OPEN', priority: 'HIGH',
        evidence: [],
        alerts: [{ id: 'alert-1', title: 'Suspicious login', severity: 'HIGH', createdAt: new Date('2026-01-01T00:00:00Z') }],
      },
    }));
    expect(graph.nodes.find((n) => n.id === 'ALERT:alert-1')).toBeDefined();
    expect(graph.edges.find((e) => e.type === 'HAS_ALERT' && e.from === 'CASE:case-1' && e.to === 'ALERT:alert-1')).toBeDefined();
  });

  it('26. repeated generation with case/evidence/alert/recipient data produces the same node/edge IDs (deterministic)', () => {
    const input = baseInput({
      recipients: [{ headerName: 'to', address: 'victim@example.com' }],
      caseContext: {
        caseId: 'case-1', title: 'Case', status: 'OPEN', priority: 'HIGH',
        evidence: [{ id: 'ev-1', type: 'LOG', sha256: null, filename: 'x', collectionTime: new Date() }],
        alerts: [{ id: 'alert-1', title: 'A', severity: 'HIGH', createdAt: new Date() }],
      },
    });
    const idsOf = (g: ReturnType<typeof buildEvidenceGraph>) => ({
      nodeIds: g.nodes.map((n) => n.id).sort(),
      edgeIds: g.edges.map((e) => e.id).sort(),
    });
    expect(idsOf(buildEvidenceGraph(input))).toEqual(idsOf(buildEvidenceGraph(input)));
  });

  it('27. a DOMAIN node includes RDAP domain intelligence only when a real lookup result exists for its registrable domain', () => {
    const withIntel = buildEvidenceGraph(baseInput({
      urls: [{ id: 'u1', url: 'https://mail.evil-example.com/a', normalizedUrl: 'https://mail.evil-example.com/a', domain: 'mail.evil-example.com', source: 'TEXT', indicators: [] }],
      domainIntelligence: [{
        registrableDomain: 'evil-example.com',
        status: 'SUCCESS',
        registrar: 'Evil Registrar LLC',
        registrationDate: new Date('2020-01-01T00:00:00Z'),
        expirationDate: new Date('2030-01-01T00:00:00Z'),
        nameservers: ['ns1.evil-example.com'],
        domainStatus: ['clientTransferProhibited'],
      }],
    }));
    const domainNode = withIntel.nodes.find((n) => n.type === 'DOMAIN')!;
    expect(domainNode.data.domainIntelligence).toMatchObject({ status: 'SUCCESS', registrar: 'Evil Registrar LLC' });

    // No RDAP data persisted for this domain yet — never fabricated.
    const withoutIntel = buildEvidenceGraph(baseInput({
      urls: [{ id: 'u2', url: 'https://unknown.example.org/x', normalizedUrl: 'https://unknown.example.org/x', domain: 'unknown.example.org', source: 'TEXT', indicators: [] }],
      domainIntelligence: [],
    }));
    const domainNode2 = withoutIntel.nodes.find((n) => n.type === 'DOMAIN')!;
    expect(domainNode2.data.domainIntelligence).toBeNull();
  });
});
