import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma, SYSTEM_ENFORCED_PERMISSIONS } from '@ciperscope/database';
import rbacPlugin from '../../../plugins/rbac';
import tolerantJsonBodyParser from '../../../plugins/tolerantJsonBodyParser';
import settingsRoutes from '../settings.routes';

/**
 * Organization Settings (GET/PATCH /settings) — reuses the existing
 * Organization.name field and the previously-unused SystemSetting table
 * (key/value per organization), no new model.
 */
describe('Organization Settings API (Integration)', () => {
  let server: FastifyInstance;
  let orgA: string;
  let orgB: string;
  let adminUserA: string;
  let readOnlyUserA: string;
  let userB: string;
  let adminSessionA: string;
  let readOnlySessionA: string;
  let sessionB: string;
  let adminTokenA: string;
  let readOnlyTokenA: string;
  let tokenB: string;

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
    server.register(fastifyJwt, { secret: 'test-settings-api-secret' });
    server.register(rbacPlugin);
    server.register(settingsRoutes, { prefix: '/api/v1/settings' });
    await server.ready();

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    adminUserA = crypto.randomUUID();
    readOnlyUserA = crypto.randomUUID();
    userB = crypto.randomUUID();
    adminSessionA = crypto.randomUUID();
    readOnlySessionA = crypto.randomUUID();
    sessionB = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [{ id: orgA, name: 'Settings Test Org A' }, { id: orgB, name: 'Settings Test Org B' }],
    });
    await prisma.user.createMany({
      data: [
        { id: adminUserA, email: `settings-admin-a-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: readOnlyUserA, email: `settings-ro-a-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userB, email: `settings-b-${Date.now()}@test.local`, passwordHash: 'dummy' },
      ],
    });
    await prisma.session.createMany({
      data: [
        { id: adminSessionA, userId: adminUserA, expiresAt: new Date(Date.now() + 100000) },
        { id: readOnlySessionA, userId: readOnlyUserA, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionB, userId: userB, expiresAt: new Date(Date.now() + 100000) },
      ],
    });

    const adminRole = await prisma.role.create({ data: { name: 'Settings Admin', organizationId: orgA } });
    const readOnlyRole = await prisma.role.create({ data: { name: 'Settings Reader', organizationId: orgA } });
    const roleB = await prisma.role.create({ data: { name: 'Reader B', organizationId: orgB } });
    await grantPermissions(adminRole.id, ['USER_READ', 'USER_MANAGE']);
    await grantPermissions(readOnlyRole.id, ['USER_READ']);
    await grantPermissions(roleB.id, ['USER_READ', 'USER_MANAGE']);

    await prisma.organizationMember.create({ data: { userId: adminUserA, organizationId: orgA, roleId: adminRole.id } });
    await prisma.organizationMember.create({ data: { userId: readOnlyUserA, organizationId: orgA, roleId: readOnlyRole.id } });
    await prisma.organizationMember.create({ data: { userId: userB, organizationId: orgB, roleId: roleB.id } });

    adminTokenA = server.jwt.sign({ sub: adminUserA, orgs: [orgA], sid: adminSessionA });
    readOnlyTokenA = server.jwt.sign({ sub: readOnlyUserA, orgs: [orgA], sid: readOnlySessionA });
    tokenB = server.jwt.sign({ sub: userB, orgs: [orgB], sid: sessionB });
  });

  afterAll(async () => {
    await prisma.systemSetting.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.organizationMember.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: { in: [orgA, orgB] } } } });
    await prisma.role.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.session.deleteMany({ where: { id: { in: [adminSessionA, readOnlySessionA, sessionB] } } });
    await prisma.user.deleteMany({ where: { id: { in: [adminUserA, readOnlyUserA, userB] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
  });

  it('returns honest defaults when no settings have ever been saved', async () => {
    const res = await server.inject({
      method: 'GET', url: '/api/v1/settings',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.organization.id).toBe(orgA);
    expect(body.preferences.autoCaseRiskThreshold).toBe('NEVER');
    expect(body.preferences.evidenceRetentionDays).toBe(365);
  });

  it('updates organization profile and preferences, and persists them', async () => {
    const patchRes = await server.inject({
      method: 'PATCH', url: '/api/v1/settings',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { displayName: 'Renamed Org A', autoCaseRiskThreshold: 'HIGH', evidenceRetentionDays: 90, notifyOnCriticalCase: false },
    });
    expect(patchRes.statusCode).toBe(200);
    expect(patchRes.json().organization.name).toBe('Renamed Org A');
    expect(patchRes.json().preferences.autoCaseRiskThreshold).toBe('HIGH');
    expect(patchRes.json().preferences.evidenceRetentionDays).toBe(90);
    expect(patchRes.json().preferences.notifyOnCriticalCase).toBe(false);

    const getRes = await server.inject({
      method: 'GET', url: '/api/v1/settings',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
    });
    expect(getRes.json().organization.name).toBe('Renamed Org A');
    expect(getRes.json().preferences.evidenceRetentionDays).toBe(90);
  });

  it('never returns secrets/tokens in the response body', async () => {
    const res = await server.inject({
      method: 'GET', url: '/api/v1/settings',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
    });
    expect(JSON.stringify(res.json())).not.toMatch(/accessToken|refreshToken|secretEncrypted|passwordHash/i);
  });

  it('tenant isolation — org A settings changes never affect org B', async () => {
    const res = await server.inject({
      method: 'GET', url: '/api/v1/settings',
      headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
    });
    expect(res.json().organization.name).toBe('Settings Test Org B');
    expect(res.json().preferences.evidenceRetentionDays).toBe(365);
  });

  it('a PATCH sent under org B context only ever updates org B, never org A (org context always comes from the header, never trusted from elsewhere)', async () => {
    const res = await server.inject({
      method: 'PATCH', url: '/api/v1/settings',
      headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      payload: { displayName: 'Org B Renamed' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().organization.id).toBe(orgB);

    const orgAStillIntact = await prisma.organization.findUnique({ where: { id: orgA } });
    expect(orgAStillIntact?.name).toBe('Renamed Org A');
  });

  it('a read-only (USER_READ only) user cannot update settings', async () => {
    const res = await server.inject({
      method: 'PATCH', url: '/api/v1/settings',
      headers: { authorization: `Bearer ${readOnlyTokenA}`, 'x-organization-id': orgA },
      payload: { displayName: 'Should not work' },
    });
    expect(res.statusCode).toBe(403);
  });

  it('rejects an unauthenticated request', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/settings' });
    expect(res.statusCode).toBe(401);
  });

  it('rejects a request with no organization context', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/settings', headers: { authorization: `Bearer ${adminTokenA}` } });
    expect(res.statusCode).toBe(400);
  });

  it('rejects an empty update body', async () => {
    const res = await server.inject({
      method: 'PATCH', url: '/api/v1/settings',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: {},
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects an invalid autoCaseRiskThreshold value', async () => {
    const res = await server.inject({
      method: 'PATCH', url: '/api/v1/settings',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { autoCaseRiskThreshold: 'ULTRA' },
    });
    expect(res.statusCode).toBe(400);
  });
});
