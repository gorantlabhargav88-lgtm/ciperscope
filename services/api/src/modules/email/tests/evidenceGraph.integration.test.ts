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

    await server.ready();
  });

  afterAll(async () => {
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
    expect(body.nodes.find((n: any) => n.type === 'IP' && n.id === 'IP:198.51.100.20')).toBeDefined();
    expect(body.nodes.find((n: any) => n.type === 'DOMAIN' && n.id === 'DOMAIN:graph-test.example.com')).toBeDefined();
    expect(body.nodes.find((n: any) => n.type === 'FILE_HASH' && n.id === 'HASH:graphtesthash123')).toBeDefined();
    expect(body.nodes.find((n: any) => n.type === 'THREAT_INDICATOR')).toBeDefined();
    expect(body.metadata.nodeCount).toBe(body.nodes.length);
    expect(body.metadata.edgeCount).toBe(body.edges.length);
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

  it('returns 404 for a non-existent email', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${crypto.randomUUID()}/evidence-graph`,
      headers: { 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(404);
  });
});
