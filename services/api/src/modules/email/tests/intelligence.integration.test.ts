import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyMultipart from '@fastify/multipart';
import emailRoutes from '../email.routes';
import { prisma } from '@ciperscope/database';
import { createRedisConnection } from '@ciperscope/queue';
import { env } from '@ciperscope/config';
import crypto from 'crypto';

/**
 * Phase H — GET /:emailId/intelligence: joins already-persisted relay-hop
 * IPs, their deterministic classification, GeoLocation rows, and CTI
 * ThreatIntelObservation verdicts. Real Postgres, real tenant-scoping via
 * the route's own `where: { id, organizationId }` — only auth/RBAC
 * middleware is mocked (covered elsewhere), matching the existing
 * ingestion.integration.test.ts convention in this same directory.
 */
describe('GET /:emailId/intelligence (Integration)', () => {
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
        if (!request.headers['x-organization-id']) {
          throw new Error('Tenant isolation failed');
        }
      };
    });

    server.register(emailRoutes, { prefix: '/api/v1/emails' });

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    await prisma.organization.createMany({
      data: [{ id: orgA, name: 'Intelligence Test Org A' }, { id: orgB, name: 'Intelligence Test Org B' }],
    });

    const email = await prisma.email.create({
      data: {
        organizationId: orgA,
        sha256: crypto.randomBytes(32).toString('hex'),
        analysisStatus: 'COMPLETED',
      },
    });
    emailAId = email.id;

    await prisma.relayHop.createMany({
      data: [
        { emailId: emailAId, hopOrder: 0, sourceIp: '203.0.113.50', receivedHeader: 'from a (a [203.0.113.50]) by b' }, // has geo + reputation below
        { emailId: emailAId, hopOrder: 1, sourceIp: '10.0.0.5', receivedHeader: 'from c (c [10.0.0.5]) by d' }, // private — must be classified, never enriched
        { emailId: emailAId, hopOrder: 2, sourceIp: 'not-an-ip', receivedHeader: 'from e (e [not-an-ip]) by f' }, // malformed — must not crash the route
      ],
    });

    await prisma.emailUrl.create({
      data: { emailId: emailAId, url: 'https://example.com/a', domain: 'example.com', source: 'TEXT' },
    });

    await prisma.geoLocation.upsert({
      where: { ipAddress: '203.0.113.50' },
      create: { ipAddress: '203.0.113.50', country: 'Testland', city: 'Testville', asn: 'AS64500', isp: 'Test ISP', provider: 'MaxMind' },
      update: {},
    });

    const indicator = await prisma.indicator.create({ data: { type: 'IP', value: '203.0.113.50' } });
    await prisma.threatIntelObservation.create({
      data: { indicatorId: indicator.id, provider: 'AbuseIPDB', verdict: 'SUSPICIOUS', confidence: 42, observationTime: new Date() },
    });

    // Phase N — a PTR observation persisted by the worker's CTI pipeline,
    // scoped to this exact email.
    await prisma.dnsObservation.create({
      data: {
        emailId: emailAId, queryName: '203.0.113.50', recordType: 'PTR',
        response: JSON.stringify(['relay.example.net']), rcode: 'NOERROR', durationMs: 14,
      },
    });

    await server.ready();
  });

  afterAll(async () => {
    await prisma.dnsObservation.deleteMany({ where: { emailId: emailAId } });
    await prisma.threatIntelObservation.deleteMany({ where: { indicator: { value: '203.0.113.50' } } });
    await prisma.indicator.deleteMany({ where: { value: '203.0.113.50' } });
    await prisma.geoLocation.deleteMany({ where: { ipAddress: '203.0.113.50' } });
    await prisma.emailUrl.deleteMany({ where: { emailId: emailAId } });
    await prisma.relayHop.deleteMany({ where: { emailId: emailAId } });
    await prisma.email.deleteMany({ where: { id: emailAId } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
    const redis = createRedisConnection(env.REDIS_URL || 'redis://127.0.0.1:6379');
    await redis.quit();
  });

  it('classifies a public IP and attaches its persisted geolocation and reputation', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailAId}/intelligence`,
      headers: { 'x-organization-id': orgA },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    const publicEntry = body.ipIntelligence.find((e: any) => e.ip === '203.0.113.50');

    expect(publicEntry.classification).toBe('DOCUMENTATION'); // 203.0.113.0/24 is a TEST-NET range
    expect(publicEntry.geolocation).toEqual(
      expect.objectContaining({ country: 'Testland', city: 'Testville', asn: 'AS64500', provider: 'MaxMind' })
    );
    expect(publicEntry.reputation).toEqual(
      expect.objectContaining({ verdict: 'SUSPICIOUS', confidence: 42, provider: 'AbuseIPDB' })
    );
    expect(publicEntry.reverseDns).toEqual(['relay.example.net']);
  });

  it('never fabricates reverseDns for an IP with no persisted PTR observation', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailAId}/intelligence`,
      headers: { 'x-organization-id': orgA },
    });

    const privateEntry = res.json().ipIntelligence.find((e: any) => e.ip === '10.0.0.5');
    expect(privateEntry.reverseDns).toBeNull();
  });

  it('classifies a private IP correctly and never fabricates geolocation/reputation for it', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailAId}/intelligence`,
      headers: { 'x-organization-id': orgA },
    });

    const privateEntry = res.json().ipIntelligence.find((e: any) => e.ip === '10.0.0.5');
    expect(privateEntry.classification).toBe('PRIVATE');
    expect(privateEntry.isRoutablePublic).toBe(false);
    expect(privateEntry.geolocation).toBeNull();
    expect(privateEntry.reputation).toBeNull();
  });

  it('handles a malformed relay-hop IP without crashing the route', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailAId}/intelligence`,
      headers: { 'x-organization-id': orgA },
    });

    expect(res.statusCode).toBe(200);
    const malformedEntry = res.json().ipIntelligence.find((e: any) => e.ip === 'not-an-ip');
    expect(malformedEntry.classification).toBe('INVALID');
  });

  it('aggregates domains from EmailUrl.domain', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailAId}/intelligence`,
      headers: { 'x-organization-id': orgA },
    });

    expect(res.json().domains).toEqual(expect.arrayContaining([
      expect.objectContaining({ domain: 'example.com', urlCount: 1 }),
    ]));
  });

  it('domains have no RDAP intelligence attached when none has been persisted yet — never fabricated', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailAId}/intelligence`,
      headers: { 'x-organization-id': orgA },
    });

    const entry = res.json().domains.find((d: any) => d.domain === 'example.com');
    expect(entry.domainIntelligence).toBeNull();
  });

  it('attaches persisted RDAP domain intelligence, read-only (no live RDAP call from this route)', async () => {
    await prisma.domainIntelligence.upsert({
      where: { registrableDomain: 'example.com' },
      create: {
        registrableDomain: 'example.com', status: 'SUCCESS', registrar: 'Test Registrar, Inc.',
        registrationDate: new Date('1995-08-14T00:00:00Z'), expirationDate: new Date('2030-08-13T00:00:00Z'),
        nameservers: ['a.iana-servers.net', 'b.iana-servers.net'], domainStatus: ['clientTransferProhibited'], rdapSource: 'https://rdap.verisign.com/com/v1/',
      },
      update: {},
    });

    try {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/emails/${emailAId}/intelligence`,
        headers: { 'x-organization-id': orgA },
      });
      const entry = res.json().domains.find((d: any) => d.domain === 'example.com');
      expect(entry.domainIntelligence).toEqual(expect.objectContaining({
        registrableDomain: 'example.com', status: 'SUCCESS', registrar: 'Test Registrar, Inc.',
        nameservers: ['a.iana-servers.net', 'b.iana-servers.net'],
      }));
    } finally {
      await prisma.domainIntelligence.deleteMany({ where: { registrableDomain: 'example.com' } });
    }
  });

  it('tenant isolation — a different organization cannot view this email\'s intelligence', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailAId}/intelligence`,
      headers: { 'x-organization-id': orgB },
    });

    expect(res.statusCode).toBe(404);
  });

  it('rejects a request with no tenant context', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailAId}/intelligence`,
    });
    expect(res.statusCode).toBe(500); // mocked requirePermission throws (real RBAC/tenant-context enforcement is covered elsewhere)
  });
});
