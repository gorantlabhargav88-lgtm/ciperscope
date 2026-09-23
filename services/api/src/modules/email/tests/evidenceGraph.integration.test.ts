import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyMultipart from '@fastify/multipart';
import emailRoutes from '../email.routes';
import { prisma } from '@ciperscope/database';
import { createRedisConnection } from '@ciperscope/queue';
import { env } from '@ciperscope/config';
import crypto from 'crypto';

/**
 * Phase I — GET /:emailId/evidence-graph: real Postgres, real join of
 * relay hops/URLs/attachments/geo/CTI into the deterministic graph builder.
 * Same mocked-auth convention as ingestion.integration.test.ts and
 * intelligence.integration.test.ts in this directory (RBAC itself is
 * covered elsewhere) — this proves the route's own DB query + tenant
 * scoping + graph assembly.
 */
describe('GET /:emailId/evidence-graph (Integration)', () => {
  let server: FastifyInstance;
  let orgA: string;
  let orgB: string;
  let emailAId: string;

  beforeAll(async () => {
    server = Fastify();
    server.register(fastifyMultipart);
    server.decorate('authenticate', async () => {});
    server.decorate('requirePermission', () => {
      return async (request: { headers: Record<string, string> }) => {
        if (!request.headers['x-organization-id']) throw new Error('Tenant isolation failed');
      };
    });
    server.register(emailRoutes, { prefix: '/api/v1/emails' });

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    await prisma.organization.createMany({
      data: [{ id: orgA, name: 'Evidence Graph Test Org A' }, { id: orgB, name: 'Evidence Graph Test Org B' }],
    });

    const email = await prisma.email.create({
      data: { organizationId: orgA, sha256: crypto.randomBytes(32).toString('hex'), analysisStatus: 'COMPLETED', senderAddress: 'sender@example.com' },
    });
    emailAId = email.id;

    await prisma.relayHop.create({
      data: { emailId: emailAId, hopOrder: 0, sourceIp: '198.51.100.20', receivedHeader: 'from a (a [198.51.100.20]) by b' },
    });

    await prisma.emailUrl.create({
      data: { emailId: emailAId, url: 'https://graph-test.example.com/a', normalizedUrl: 'https://graph-test.example.com/a', domain: 'graph-test.example.com', source: 'TEXT', indicators: ['SOME_INDICATOR'] },
    });

    await prisma.emailAttachment.create({
      data: { emailId: emailAId, filename: 'evidence.pdf', mimeType: 'application/pdf', sizeBytes: 100, sha256: 'graphtesthash123' },
    });

    // Phase N — a PTR observation persisted by the worker's CTI pipeline.
    await prisma.dnsObservation.create({
      data: {
        emailId: emailAId, queryName: '198.51.100.20', recordType: 'PTR',
        response: JSON.stringify(['relay.graph-test.example']), rcode: 'NOERROR', durationMs: 9,
      },
    });

    await server.ready();
  });

  afterAll(async () => {
    await prisma.dnsObservation.deleteMany({ where: { emailId: emailAId } });
    await prisma.emailAttachment.deleteMany({ where: { emailId: emailAId } });
    await prisma.emailUrl.deleteMany({ where: { emailId: emailAId } });
    await prisma.relayHop.deleteMany({ where: { emailId: emailAId } });
    await prisma.email.deleteMany({ where: { id: emailAId } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
    const redis = createRedisConnection(env.REDIS_URL || 'redis://127.0.0.1:6379');
    await redis.quit();
  });

  it('returns a graph joining relay IP, URL/domain, and attachment/hash evidence for the owning org', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailAId}/evidence-graph`,
      headers: { 'x-organization-id': orgA },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.emailId).toBe(emailAId);
    expect(body.nodes.find((n: any) => n.type === 'EMAIL')).toBeDefined();
    const ipNode = body.nodes.find((n: any) => n.type === 'IP' && n.id === 'IP:198.51.100.20');
    expect(ipNode).toBeDefined();
    expect(ipNode.data).toEqual(expect.objectContaining({ reverseDns: ['relay.graph-test.example'] }));
    expect(body.nodes.find((n: any) => n.type === 'DOMAIN' && n.id === 'DOMAIN:graph-test.example.com')).toBeDefined();
    expect(body.nodes.find((n: any) => n.type === 'FILE_HASH' && n.id === 'HASH:graphtesthash123')).toBeDefined();
    expect(body.nodes.find((n: any) => n.type === 'THREAT_INDICATOR')).toBeDefined();
    expect(body.metadata.nodeCount).toBe(body.nodes.length);
    expect(body.metadata.edgeCount).toBe(body.edges.length);
  });

  it('attaches persisted RDAP domain intelligence to the matching DOMAIN node (Phase L)', async () => {
    // A dedicated, test-unique URL/domain — never shared with another test
    // file's registrable domain, so the DomainIntelligence unique-key
    // upsert here can never race with unrelated concurrently-run tests.
    const uniqueDomain = `rdap-graph-test-${Date.now()}.example`;
    const rdapUrl = await prisma.emailUrl.create({
      data: { emailId: emailAId, url: `https://${uniqueDomain}/x`, domain: uniqueDomain, source: 'TEXT' },
    });
    await prisma.domainIntelligence.create({
      data: { registrableDomain: uniqueDomain, status: 'SUCCESS', registrar: 'Graph Test Registrar' },
    });

    try {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/emails/${emailAId}/evidence-graph`,
        headers: { 'x-organization-id': orgA },
      });
      const domainNode = res.json().nodes.find((n: any) => n.id === `DOMAIN:${uniqueDomain}`);
      expect(domainNode.data.domainIntelligence).toEqual(expect.objectContaining({ status: 'SUCCESS', registrar: 'Graph Test Registrar' }));
    } finally {
      await prisma.domainIntelligence.deleteMany({ where: { registrableDomain: uniqueDomain } });
      await prisma.emailUrl.deleteMany({ where: { id: rdapUrl.id } });
    }
  });

  it('tenant isolation — a different organization cannot fetch this email\'s evidence graph', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailAId}/evidence-graph`,
      headers: { 'x-organization-id': orgB },
    });
    expect(res.statusCode).toBe(404);
  });

  it('rejects a request with no tenant context', async () => {
    const res = await server.inject({ method: 'GET', url: `/api/v1/emails/${emailAId}/evidence-graph` });
    expect(res.statusCode).toBe(500); // mocked requirePermission throws; real RBAC covered elsewhere
  });

  it('repeated requests for the same email produce a graph with the same node/edge IDs (deterministic)', async () => {
    const res1 = await server.inject({ method: 'GET', url: `/api/v1/emails/${emailAId}/evidence-graph`, headers: { 'x-organization-id': orgA } });
    const res2 = await server.inject({ method: 'GET', url: `/api/v1/emails/${emailAId}/evidence-graph`, headers: { 'x-organization-id': orgA } });

    const idsOf = (body: any) => ({ nodeIds: body.nodes.map((n: any) => n.id).sort(), edgeIds: body.edges.map((e: any) => e.id).sort() });
    expect(idsOf(res1.json())).toEqual(idsOf(res2.json()));
  });

  it('never returns raw email content, OAuth tokens, or attachment bytes', async () => {
    const res = await server.inject({ method: 'GET', url: `/api/v1/emails/${emailAId}/evidence-graph`, headers: { 'x-organization-id': orgA } });
    const serialized = res.body.toLowerCase();
    expect(serialized).not.toMatch(/accesstoken|refreshtoken|rawstoragekey|secretencrypted/);
  });

  it('rejects a malformed (non-UUID) emailId with 400, not a 500', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/not-a-real-uuid/evidence-graph`,
      headers: { 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(400);
  });

  it('returns 404 for a non-existent email', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${crypto.randomUUID()}/evidence-graph`,
      headers: { 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(404);
  });

  describe('case-linked email (Phase J: SENDER/RECIPIENT/CASE/EVIDENCE/ALERT)', () => {
    let caseId: string;
    let emailBId: string;

    beforeAll(async () => {
      const c = await prisma.case.create({ data: { organizationId: orgA, title: 'Graph Test Case' } });
      caseId = c.id;

      const emailB = await prisma.email.create({
        data: { organizationId: orgA, caseId, sha256: crypto.randomBytes(32).toString('hex'), analysisStatus: 'COMPLETED', senderAddress: 'attacker@evil.example' },
      });
      emailBId = emailB.id;

      await prisma.emailAddress.create({
        data: { emailId: emailBId, headerName: 'to', address: 'victim@example.com', raw: 'victim@example.com' },
      });

      await prisma.evidence.create({
        data: { organizationId: orgA, caseId, type: 'LOG', storageKey: 'k', sha256: crypto.randomBytes(32).toString('hex'), status: 'ACTIVE' },
      });

      await prisma.alert.create({
        data: { organizationId: orgA, caseId, title: 'Suspicious relay', message: 'test', severity: 'HIGH' },
      });
    });

    afterAll(async () => {
      await prisma.alert.deleteMany({ where: { caseId } });
      await prisma.evidence.deleteMany({ where: { caseId } });
      await prisma.emailAddress.deleteMany({ where: { emailId: emailBId } });
      await prisma.email.deleteMany({ where: { id: emailBId } });
      await prisma.case.deleteMany({ where: { id: caseId } });
    });

    it('produces SENDER, RECIPIENT, CASE, EVIDENCE, and ALERT nodes for a case-linked email', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/emails/${emailBId}/evidence-graph`,
        headers: { 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();

      expect(body.nodes.find((n: any) => n.type === 'SENDER' && n.id === 'SENDER:attacker@evil.example')).toBeDefined();
      expect(body.nodes.find((n: any) => n.type === 'RECIPIENT' && n.id === 'RECIPIENT:victim@example.com')).toBeDefined();
      expect(body.nodes.find((n: any) => n.type === 'CASE' && n.id === `CASE:${caseId}`)).toBeDefined();
      expect(body.nodes.find((n: any) => n.type === 'EVIDENCE')).toBeDefined();
      expect(body.nodes.find((n: any) => n.type === 'ALERT')).toBeDefined();
      expect(body.edges.find((e: any) => e.type === 'BELONGS_TO_CASE')).toBeDefined();
      expect(body.edges.find((e: any) => e.type === 'EMAIL_GENERATED_EVIDENCE')).toBeDefined();
      expect(body.edges.find((e: any) => e.type === 'HAS_ALERT')).toBeDefined();
    });

    it('an email with no case never produces CASE/EVIDENCE/ALERT nodes (no fabricated linkage)', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/emails/${emailAId}/evidence-graph`,
        headers: { 'x-organization-id': orgA },
      });
      const body = res.json();
      expect(body.nodes.find((n: any) => ['CASE', 'EVIDENCE', 'ALERT'].includes(n.type))).toBeUndefined();
    });

    it('tenant isolation holds for the case-linked graph too', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/emails/${emailBId}/evidence-graph`,
        headers: { 'x-organization-id': orgB },
      });
      expect(res.statusCode).toBe(404);
    });
  });

  describe('live E2E — full evidence vector set (Phase J Step 10)', () => {
    let emailCId: string;
    let indicatorIpId: string;

    beforeAll(async () => {
      const emailC = await prisma.email.create({
        data: { organizationId: orgA, sha256: crypto.randomBytes(32).toString('hex'), analysisStatus: 'COMPLETED', senderAddress: 'phisher@evil-e2e.example' },
      });
      emailCId = emailC.id;

      // Relay IP
      await prisma.relayHop.create({
        data: { emailId: emailCId, hopOrder: 0, sourceIp: '203.0.113.77', receivedHeader: 'from x (x [203.0.113.77]) by y' },
      });

      // Normal URL
      await prisma.emailUrl.create({
        data: { emailId: emailCId, url: 'https://e2e-normal.example.com/page', domain: 'e2e-normal.example.com', source: 'TEXT', indicators: [] },
      });

      // QR-decoded URL — dual-write mirrors the real QrCodeAnalyzer: the
      // decoded payload is both an EmailUrl (source QR_CODE) and referenced
      // from the attachment's qrFindings.
      const qrUrl = 'https://e2e-qr.example.com/redirect';
      await prisma.emailUrl.create({
        data: { emailId: emailCId, url: qrUrl, domain: 'e2e-qr.example.com', source: 'QR_CODE', indicators: [] },
      });

      // Attachment with a QR code decoding to the URL above
      await prisma.emailAttachment.create({
        data: {
          emailId: emailCId, filename: 'invoice-qr.png', mimeType: 'image/png', sizeBytes: 4096,
          sha256: crypto.createHash('sha256').update('e2e-fake-image').digest('hex'),
          qrFindings: { detected: true, codes: [{ type: 'URL', payload: qrUrl }] },
        },
      });

      // CTI observation on the relay IP — a real Indicator + ThreatIntelObservation row.
      const ipIndicator = await prisma.indicator.create({ data: { type: 'IP', value: '203.0.113.77' } });
      indicatorIpId = ipIndicator.id;
      await prisma.threatIntelObservation.create({
        data: { indicatorId: ipIndicator.id, provider: 'AbuseIPDB', verdict: 'MALICIOUS', confidence: 91 },
      });
    });

    afterAll(async () => {
      await prisma.threatIntelObservation.deleteMany({ where: { indicatorId: indicatorIpId } });
      await prisma.indicator.deleteMany({ where: { id: indicatorIpId } });
      await prisma.emailAttachment.deleteMany({ where: { emailId: emailCId } });
      await prisma.emailUrl.deleteMany({ where: { emailId: emailCId } });
      await prisma.relayHop.deleteMany({ where: { emailId: emailCId } });
      await prisma.email.deleteMany({ where: { id: emailCId } });
    });

    it('the graph reflects every real persisted vector: URL, attachment, QR-decoded URL, relay IP, and CTI observation', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/emails/${emailCId}/evidence-graph`,
        headers: { 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();

      // Relay IP
      const ipNode = body.nodes.find((n: any) => n.id === 'IP:203.0.113.77');
      expect(ipNode).toBeDefined();

      // Normal URL
      expect(body.nodes.find((n: any) => n.id === 'URL:https://e2e-normal.example.com/page')).toBeDefined();

      // QR code node + decoded URL + edges
      const qrNode = body.nodes.find((n: any) => n.type === 'QR_CODE');
      expect(qrNode).toBeDefined();
      expect(qrNode.data.payload).toBe('https://e2e-qr.example.com/redirect');
      const qrUrlNode = body.nodes.find((n: any) => n.id === 'URL:https://e2e-qr.example.com/redirect');
      expect(qrUrlNode).toBeDefined();
      expect(body.edges.find((e: any) => e.type === 'DECODED_TO_URL' && e.from === qrNode.id && e.to === qrUrlNode.id)).toBeDefined();

      // CTI observation on the relay IP, linked to the real IP node
      const ctiNode = body.nodes.find((n: any) => n.type === 'CTI_INDICATOR' && n.id === 'CTI:203.0.113.77');
      expect(ctiNode).toBeDefined();
      expect(ctiNode.data.verdict).toBe('MALICIOUS');
      expect(body.edges.find((e: any) => e.type === 'OBSERVED_BY_CTI' && e.from === ipNode.id && e.to === ctiNode.id)).toBeDefined();

      // Every node/edge carries provenance pointing back to a real source record.
      for (const node of body.nodes) {
        expect(node.provenance.length).toBeGreaterThan(0);
      }
    });
  });
});
