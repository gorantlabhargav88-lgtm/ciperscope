import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma, SYSTEM_ENFORCED_PERMISSIONS, PermissionAction } from '@ciperscope/database';
import rbacPlugin from '../plugins/rbac';
import alertRoutes from '../modules/alert/alert.routes';
import investigationRoutes from '../modules/investigation/investigation.routes';
import evidenceRoutes from '../modules/evidence/evidence.routes';

/**
 * Applies the exact idempotent upsert pattern used by
 * packages/database/prisma/seed.ts to grant SYSTEM_ADMIN every permission
 * the API enforces. Imports the same SYSTEM_ENFORCED_PERMISSIONS manifest
 * seed.ts uses (rather than a duplicated permission list), so this test
 * fails if seed.ts and the route call sites ever drift apart again.
 */
async function grantSystemEnforcedPermissions(roleId: string): Promise<void> {
  for (const p of SYSTEM_ENFORCED_PERMISSIONS) {
    const permission = await prisma.permission.upsert({
      where: { action: p.action },
      update: {},
      create: { action: p.action, description: p.description },
    });
    await prisma.rolePermission.upsert({
      where: { roleId_permissionId: { roleId, permissionId: permission.id } },
      update: {},
      create: { roleId, permissionId: permission.id },
    });
  }
}

describe('RBAC seed regression (SYSTEM_ENFORCED_PERMISSIONS)', () => {
  let server: FastifyInstance;
  let orgId: string;
  let fullRoleId: string;
  let noPermRoleId: string;
  let userWithAllId: string;
  let userWithNoneId: string;
  let sessionWithAllId: string;
  let sessionWithNoneId: string;
  let tokenWithAll: string;
  let tokenWithNone: string;

  beforeAll(async () => {
    server = Fastify();
    server.register(fastifyJwt, { secret: 'test-rbac-seed-secret' });
    server.register(rbacPlugin);
    server.register(alertRoutes, { prefix: '/api/v1/alerts' });
    server.register(investigationRoutes, { prefix: '/api/v1/investigations' });
    server.register(evidenceRoutes, { prefix: '/api/v1/evidence' });
    await server.ready();

    orgId = crypto.randomUUID();
    await prisma.organization.create({ data: { id: orgId, name: 'RBAC Seed Test Org' } });

    const fullRole = await prisma.role.create({ data: { name: 'Full Permissions (test)', organizationId: orgId } });
    const noPermRole = await prisma.role.create({ data: { name: 'No Permissions (test)', organizationId: orgId } });
    fullRoleId = fullRole.id;
    noPermRoleId = noPermRole.id;

    // Apply the seed manifest twice up front — checkpoints C/D assert this produced no duplicates.
    await grantSystemEnforcedPermissions(fullRoleId);
    await grantSystemEnforcedPermissions(fullRoleId);

    userWithAllId = crypto.randomUUID();
    userWithNoneId = crypto.randomUUID();
    await prisma.user.createMany({
      data: [
        { id: userWithAllId, email: `rbac-seed-all-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userWithNoneId, email: `rbac-seed-none-${Date.now()}@test.local`, passwordHash: 'dummy' },
      ],
    });

    sessionWithAllId = crypto.randomUUID();
    sessionWithNoneId = crypto.randomUUID();
    await prisma.session.createMany({
      data: [
        { id: sessionWithAllId, userId: userWithAllId, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionWithNoneId, userId: userWithNoneId, expiresAt: new Date(Date.now() + 100000) },
      ],
    });

    await prisma.organizationMember.create({ data: { userId: userWithAllId, organizationId: orgId, roleId: fullRoleId } });
    await prisma.organizationMember.create({ data: { userId: userWithNoneId, organizationId: orgId, roleId: noPermRoleId } });

    tokenWithAll = server.jwt.sign({ sub: userWithAllId, orgs: [orgId], sid: sessionWithAllId });
    tokenWithNone = server.jwt.sign({ sub: userWithNoneId, orgs: [orgId], sid: sessionWithNoneId });
  });

  afterAll(async () => {
    await prisma.organizationMember.deleteMany({ where: { userId: { in: [userWithAllId, userWithNoneId] } } });
    await prisma.session.deleteMany({ where: { id: { in: [sessionWithAllId, sessionWithNoneId] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userWithAllId, userWithNoneId] } } });
    await prisma.rolePermission.deleteMany({ where: { roleId: { in: [fullRoleId, noPermRoleId] } } });
    await prisma.role.deleteMany({ where: { id: { in: [fullRoleId, noPermRoleId] } } });
    await prisma.organization.deleteMany({ where: { id: orgId } });
    await server.close();
  });

  it('B/E: a role seeded via the manifest holds every one of the 13 enforced permissions, by name, not just count', async () => {
    const role = await prisma.role.findUniqueOrThrow({
      where: { id: fullRoleId },
      include: { permissions: { include: { permission: true } } },
    });
    const grantedActions = new Set(role.permissions.map((rp) => rp.permission.action));
    const requiredActions: PermissionAction[] = SYSTEM_ENFORCED_PERMISSIONS.map((p) => p.action);

    for (const action of requiredActions) {
      expect(grantedActions.has(action)).toBe(true);
    }
    expect(grantedActions.size).toBe(requiredActions.length);
  });

  it('C: seeding the same manifest twice creates no duplicate Permission rows', async () => {
    for (const p of SYSTEM_ENFORCED_PERMISSIONS) {
      const rows = await prisma.permission.findMany({ where: { action: p.action } });
      expect(rows.length).toBe(1);
    }
  });

  it('D: seeding the same manifest twice creates no duplicate RolePermission rows', async () => {
    const rolePermissions = await prisma.rolePermission.findMany({ where: { roleId: fullRoleId } });
    expect(rolePermissions.length).toBe(SYSTEM_ENFORCED_PERMISSIONS.length);
  });

  // These three routes (alert, investigation, evidence) had zero real-RBAC integration
  // coverage before this file — case/email permission enforcement is already covered by
  // services/api/src/modules/case/tests/case.integration.test.ts and is intentionally not
  // duplicated here.
  const realRouteChecks: Array<{ action: PermissionAction; url: string }> = [
    { action: 'ALERT_READ', url: '/api/v1/alerts' },
    { action: 'INVESTIGATION_READ', url: '/api/v1/investigations' },
    { action: 'EVIDENCE_READ', url: '/api/v1/evidence' },
  ];

  for (const check of realRouteChecks) {
    it(`E/F/G: ${check.action} — granted role succeeds, ungranted role gets 403, tenant isolation holds`, async () => {
      const withPerm = await server.inject({
        method: 'GET',
        url: check.url,
        headers: { authorization: `Bearer ${tokenWithAll}`, 'x-organization-id': orgId },
      });
      expect(withPerm.statusCode).not.toBe(403);

      const withoutPerm = await server.inject({
        method: 'GET',
        url: check.url,
        headers: { authorization: `Bearer ${tokenWithNone}`, 'x-organization-id': orgId },
      });
      expect(withoutPerm.statusCode).toBe(403);
      expect(withoutPerm.json().message).toContain(check.action);

      const wrongTenant = await server.inject({
        method: 'GET',
        url: check.url,
        headers: { authorization: `Bearer ${tokenWithAll}`, 'x-organization-id': crypto.randomUUID() },
      });
      expect(wrongTenant.statusCode).toBe(403);
      expect(wrongTenant.json().message).toContain('Tenant isolation');
    });
  }
});
