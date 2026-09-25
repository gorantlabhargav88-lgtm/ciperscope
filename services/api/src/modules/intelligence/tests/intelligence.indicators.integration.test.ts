import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma, SYSTEM_ENFORCED_PERMISSIONS } from '@ciperscope/database';
import rbacPlugin from '../../../plugins/rbac';
import tolerantJsonBodyParser from '../../../plugins/tolerantJsonBodyParser';
import intelligenceRoutes from '../intelligence.routes';

/**
 * Org-wide Indicators of Compromise (GET /intelligence/indicators) — same
 * fixture pattern as intelligence.routes.integration.test.ts (network
 * intelligence). Reuses the existing Indicator/ThreatIntelObservation
 * tables, aggregated from EmailUrl/EmailAttachment/RelayHop/EmailAddress
 * rows already persisted for the org's emails.
 */
describe('Org-wide Indicators API (Integration)', () => {
  let server: FastifyInstance;
  let orgA: string;
  let orgB: string;
  let userA: string;
  let userB: string;
  let userANoPerm: string;
  let sessionA: string;
  let sessionB: string;
  let sessionANoPerm: string;
  let tokenA: string;
  let tokenB: string;
  let tokenANoPerm: string;
  let emailAId: string;
  let caseAId: string;
  const maliciousIp = '203.0.113.7';
  const maliciousUrl = 'http://evil.example.com/phish';
  const maliciousDomain = 'evil.example.com';

  async function grantPermissions(roleId: string, actions: string[]): Promise<void> {
    for (const action of actions) {
      const perm = SYSTEM_ENFORCED_PERMISSIONS.find((p) => p.action === action);
      if (!perm) throw new Error(`Unknown permission action in test setup: ${action}`);
      const permission = await prisma.permission.upsert({
        where: { action: perm.action },
        update: {},
        create: { action: perm.action, description: perm.description },
      });
      await prisma.rolePermission.upsert({
        where: { roleId_permissionId: { roleId, permissionId: permission.id } },
        update: {},
        create: { roleId, permissionId: permission.id },
      });
    }
  }

  beforeAll(async () => {
    server = Fastify({ ajv: { customOptions: { removeAdditional: false } } });
    server.register(tolerantJsonBodyParser);
    server.register(fastifyJwt, { secret: 'test-indicators-api-secret' });
    server.register(rbacPlugin);
    server.register(intelligenceRoutes, { prefix: '/api/v1/intelligence' });
    await server.ready();

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    userA = crypto.randomUUID();
    userB = crypto.randomUUID();
    userANoPerm = crypto.randomUUID();
    sessionA = crypto.randomUUID();
    sessionB = crypto.randomUUID();
    sessionANoPerm = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [
        { id: orgA, name: 'Indicators Test Org A' },
        { id: orgB, name: 'Indicators Test Org B' },
      ],
    });
    await prisma.user.createMany({
      data: [
        { id: userA, email: `ind-a-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userB, email: `ind-b-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userANoPerm, email: `ind-a-noperm-${Date.now()}@test.local`, passwordHash: 'dummy' },
      ],
    });
    await prisma.session.createMany({
      data: [
        { id: sessionA, userId: userA, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionB, userId: userB, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionANoPerm, userId: userANoPerm, expiresAt: new Date(Date.now() + 100000) },
      ],
    });

    const roleA = await prisma.role.create({ data: { name: 'Indicators Reader A', organizationId: orgA } });
    const roleB = await prisma.role.create({ data: { name: 'Indicators Reader B', organizationId: orgB } });
    const roleANoPerm = await prisma.role.create({ data: { name: 'No Permission A', organizationId: orgA } });
    await grantPermissions(roleA.id, ['EMAIL_READ']);
    await grantPermissions(roleB.id, ['EMAIL_READ']);

    await prisma.organizationMember.create({ data: { userId: userA, organizationId: orgA, roleId: roleA.id } });
    await prisma.organizationMember.create({ data: { userId: userB, organizationId: orgB, roleId: roleB.id } });
    await prisma.organizationMember.create({ data: { userId: userANoPerm, organizationId: orgA, roleId: roleANoPerm.id } });

    tokenA = server.jwt.sign({ sub: userA, orgs: [orgA], sid: sessionA });
    tokenB = server.jwt.sign({ sub: userB, orgs: [orgB], sid: sessionB });
    tokenANoPerm = server.jwt.sign({ sub: userANoPerm, orgs: [orgA], sid: sessionANoPerm });

    const caseA = await prisma.case.create({ data: { organizationId: orgA, title: 'Indicators fixture case' } });
    caseAId = caseA.id;

    const emailA = await prisma.email.create({
      data: {
        organizationId: orgA,
        caseId: caseAId,
        sha256: crypto.createHash('sha256').update('indicators-test-email').digest('hex'),
        senderAddress: 'attacker@example.com',
        subject: 'Indicators test fixture',
      },
    });
    emailAId = emailA.id;

    await prisma.emailUrl.create({
      data: { emailId: emailAId, url: maliciousUrl, normalizedUrl: maliciousUrl, domain: maliciousDomain, source: 'TEXT' },
    });
    await prisma.relayHop.create({
      data: { emailId: emailAId, hopOrder: 0, sourceIp: maliciousIp, receivedHeader: `from x [${maliciousIp}]` },
    });

    const indicator = await prisma.indicator.upsert({
      where: { value: maliciousUrl },
      update: {},
      create: { type: 'URL', value: maliciousUrl },
    });
    await prisma.threatIntelObservation.create({
      data: { indicatorId: indicator.id, provider: 'VirusTotal', verdict: 'MALICIOUS', confidence: 0.95 },
    });
  });

  afterAll(async () => {
    await prisma.threatIntelObservation.deleteMany({ where: { indicator: { value: maliciousUrl } } });
    await prisma.indicator.deleteMany({ where: { value: maliciousUrl } });
    await prisma.relayHop.deleteMany({ where: { emailId: emailAId } });
    await prisma.emailUrl.deleteMany({ where: { emailId: emailAId } });
    await prisma.email.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.case.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.organizationMember.deleteMany({ where: { userId: { in: [userA, userB, userANoPerm] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: { in: [orgA, orgB] } } } });
    await prisma.role.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.session.deleteMany({ where: { id: { in: [sessionA, sessionB, sessionANoPerm] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userA, userB, userANoPerm] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
  });

  it('aggregates real indicators for the requesting org with CTI enrichment, never fabricated', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/intelligence/indicators',
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();

    const urlIndicator = body.items.find((i: any) => i.type === 'URL' && i.value === maliciousUrl);
    expect(urlIndicator).toBeTruthy();
    expect(urlIndicator.severity).toBe('CRITICAL');
    expect(urlIndicator.reputation).toBe('MALICIOUS');
    expect(urlIndicator.source).toBe('VirusTotal');
    expect(urlIndicator.relatedEmailCount).toBe(1);
    expect(urlIndicator.relatedCaseCount).toBe(1);

    const ipIndicator = body.items.find((i: any) => i.type === 'IP' && i.value === maliciousIp);
    expect(ipIndicator).toBeTruthy();
    expect(ipIndicator.reputation).toBe('UNKNOWN'); // honest — no CTI observation exists for this IP
    expect(ipIndicator.severity).toBeNull();

    const domainIndicator = body.items.find((i: any) => i.type === 'DOMAIN' && i.value === maliciousDomain);
    expect(domainIndicator).toBeTruthy();

    // No token/secret/credential fields ever present anywhere in the payload
    expect(JSON.stringify(body)).not.toMatch(/accessToken|refreshToken|storageKey|passwordHash/i);
  });

  it('supports type and severity filters', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/intelligence/indicators?type=URL&severity=CRITICAL',
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items.length).toBeGreaterThan(0);
    expect(body.items.every((i: any) => i.type === 'URL' && i.severity === 'CRITICAL')).toBe(true);
  });

  it('supports search', async () => {
    const res = await server.inject({
      method: 'GET',
      url: `/api/v1/intelligence/indicators?q=${encodeURIComponent(maliciousDomain)}`,
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items.every((i: any) => i.value.toLowerCase().includes(maliciousDomain.toLowerCase()))).toBe(true);
  });

  it('paginates deterministically', async () => {
    const res1 = await server.inject({
      method: 'GET',
      url: '/api/v1/intelligence/indicators?page=1&limit=1',
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    const res2 = await server.inject({
      method: 'GET',
      url: '/api/v1/intelligence/indicators?page=1&limit=1',
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    expect(res1.json().items).toEqual(res2.json().items);
    expect(res1.json().items.length).toBe(1);
    expect(res1.json().total).toBeGreaterThanOrEqual(3);
  });

  it('tenant isolation — org B never sees org A indicators', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/intelligence/indicators',
      headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items.find((i: any) => i.value === maliciousUrl)).toBeUndefined();
    expect(body.items.find((i: any) => i.value === maliciousIp)).toBeUndefined();
    expect(body.total).toBe(0);
  });

  it('rejects an unauthenticated request', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/intelligence/indicators' });
    expect(res.statusCode).toBe(401);
  });

  it('rejects a user without EMAIL_READ permission', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/intelligence/indicators',
      headers: { authorization: `Bearer ${tokenANoPerm}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(403);
  });

  it('rejects a request with no organization context', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/intelligence/indicators',
      headers: { authorization: `Bearer ${tokenA}` },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects malformed query parameters', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/intelligence/indicators?page=0',
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(400);
  });
});
