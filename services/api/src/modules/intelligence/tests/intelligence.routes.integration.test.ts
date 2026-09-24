import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma, SYSTEM_ENFORCED_PERMISSIONS } from '@ciperscope/database';
import rbacPlugin from '../../../plugins/rbac';
import tolerantJsonBodyParser from '../../../plugins/tolerantJsonBodyParser';
import intelligenceRoutes from '../intelligence.routes';

/**
 * Org-wide network intelligence (GET /intelligence/network) — backs the
 * Geo Intelligence and Infrastructure frontend pages. Aggregates RelayHop
 * (tenant-scoped via Email.organizationId) with the global GeoLocation/
 * DnsObservation tables. Same fixture pattern as evidence.routes.
 * integration.test.ts.
 */
describe('Network Intelligence API (Integration)', () => {
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
  const publicIp = '8.8.8.8'; // Google public DNS — indisputably classifies as PUBLIC
  const privateIp = '10.0.0.5';

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
    server.register(fastifyJwt, { secret: 'test-network-intel-api-secret' });
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
        { id: orgA, name: 'Network Intel Test Org A' },
        { id: orgB, name: 'Network Intel Test Org B' },
      ],
    });
    await prisma.user.createMany({
      data: [
        { id: userA, email: `net-intel-a-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userB, email: `net-intel-b-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userANoPerm, email: `net-intel-a-noperm-${Date.now()}@test.local`, passwordHash: 'dummy' },
      ],
    });
    await prisma.session.createMany({
      data: [
        { id: sessionA, userId: userA, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionB, userId: userB, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionANoPerm, userId: userANoPerm, expiresAt: new Date(Date.now() + 100000) },
      ],
    });

    const roleA = await prisma.role.create({ data: { name: 'Net Intel Reader A', organizationId: orgA } });
    const roleB = await prisma.role.create({ data: { name: 'Net Intel Reader B', organizationId: orgB } });
    const roleANoPerm = await prisma.role.create({ data: { name: 'No Permission A', organizationId: orgA } });
    await grantPermissions(roleA.id, ['EMAIL_READ']);
    await grantPermissions(roleB.id, ['EMAIL_READ']);

    await prisma.organizationMember.create({ data: { userId: userA, organizationId: orgA, roleId: roleA.id } });
    await prisma.organizationMember.create({ data: { userId: userB, organizationId: orgB, roleId: roleB.id } });
    await prisma.organizationMember.create({ data: { userId: userANoPerm, organizationId: orgA, roleId: roleANoPerm.id } });

    tokenA = server.jwt.sign({ sub: userA, orgs: [orgA], sid: sessionA });
    tokenB = server.jwt.sign({ sub: userB, orgs: [orgB], sid: sessionB });
    tokenANoPerm = server.jwt.sign({ sub: userANoPerm, orgs: [orgA], sid: sessionANoPerm });

    const emailA = await prisma.email.create({
      data: {
        organizationId: orgA,
        sha256: crypto.createHash('sha256').update('net-intel-test-email').digest('hex'),
        senderAddress: 'attacker@example.com',
        subject: 'Network intelligence test fixture',
      },
    });
    emailAId = emailA.id;

    await prisma.relayHop.createMany({
      data: [
        { emailId: emailAId, hopOrder: 0, sourceIp: publicIp, hostname: 'mail.example.com', receivedHeader: `from mail.example.com [${publicIp}]` },
        { emailId: emailAId, hopOrder: 1, sourceIp: privateIp, hostname: 'internal-relay', receivedHeader: `from internal-relay [${privateIp}]` },
      ],
    });
    await prisma.geoLocation.upsert({
      where: { ipAddress: publicIp },
      update: {},
      create: { ipAddress: publicIp, country: 'US', city: 'Ashburn', provider: 'MaxMind' },
    });
  });

  afterAll(async () => {
    await prisma.relayHop.deleteMany({ where: { emailId: emailAId } });
    await prisma.email.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.geoLocation.deleteMany({ where: { ipAddress: { in: [publicIp, privateIp] } } });
    await prisma.organizationMember.deleteMany({ where: { userId: { in: [userA, userB, userANoPerm] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: { in: [orgA, orgB] } } } });
    await prisma.role.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.session.deleteMany({ where: { id: { in: [sessionA, sessionB, sessionANoPerm] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userA, userB, userANoPerm] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
  });

  it('aggregates relay-hop IPs for the requesting org with real geolocation/classification, never fabricated', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/intelligence/network',
      headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.geoEnrichmentAvailable).toBe(true);

    const pub = body.items.find((i: any) => i.ip === publicIp);
    expect(pub).toBeTruthy();
    expect(pub.classification).toBe('PUBLIC');
    expect(pub.isRoutablePublic).toBe(true);
    expect(pub.geolocation.country).toBe('US');
    expect(pub.relatedEmailCount).toBe(1);

    const priv = body.items.find((i: any) => i.ip === privateIp);
    expect(priv).toBeTruthy();
    expect(priv.classification).not.toBe('PUBLIC');
    expect(priv.geolocation).toBeNull(); // honestly null, never a fabricated location for a private IP
  });

  it('tenant isolation — org B never sees org A relay-hop IPs', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/intelligence/network',
      headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items.find((i: any) => i.ip === publicIp)).toBeUndefined();
  });

  it('rejects an unauthenticated request', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/intelligence/network' });
    expect(res.statusCode).toBe(401);
  });

  it('rejects a user without EMAIL_READ permission', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/intelligence/network',
      headers: { authorization: `Bearer ${tokenANoPerm}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(403);
  });

  it('rejects a request with no organization context', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/intelligence/network',
      headers: { authorization: `Bearer ${tokenA}` },
    });
    expect(res.statusCode).toBe(400);
  });
});
