import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma, SYSTEM_ENFORCED_PERMISSIONS } from '@ciperscope/database';
import rbacPlugin from '../../../plugins/rbac';
import tolerantJsonBodyParser from '../../../plugins/tolerantJsonBodyParser';
import membersRoutes from '../members.routes';

/**
 * Organization Users & Roles (GET/POST/PATCH/DELETE /members) — reuses the
 * existing User/OrganizationMember/Role/Permission tables, no duplicate
 * model. Covers tenant isolation, RBAC, last-admin protection, and that
 * passwordHash/temporary passwords are never leaked outside their one-time
 * creation response.
 */
describe('Members (Users & Roles) API (Integration)', () => {
  let server: FastifyInstance;
  let orgA: string;
  let orgB: string;
  let adminUserA: string;
  let analystUserA: string;
  let noPermUserA: string;
  let userB: string;
  let adminSessionA: string;
  let analystSessionA: string;
  let noPermSessionA: string;
  let sessionB: string;
  let adminTokenA: string;
  let analystTokenA: string;
  let noPermTokenA: string;
  let tokenB: string;
  let adminRoleA: string;
  let analystRoleA: string;
  let roleB: string;
  let adminMembershipIdA: string;
  let analystMembershipIdA: string;

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
    server.register(fastifyJwt, { secret: 'test-members-api-secret' });
    server.register(rbacPlugin);
    server.register(membersRoutes, { prefix: '/api/v1/members' });
    await server.ready();

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    adminUserA = crypto.randomUUID();
    analystUserA = crypto.randomUUID();
    noPermUserA = crypto.randomUUID();
    userB = crypto.randomUUID();
    adminSessionA = crypto.randomUUID();
    analystSessionA = crypto.randomUUID();
    noPermSessionA = crypto.randomUUID();
    sessionB = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [{ id: orgA, name: 'Members Test Org A' }, { id: orgB, name: 'Members Test Org B' }],
    });
    await prisma.user.createMany({
      data: [
        { id: adminUserA, email: `members-admin-a-${Date.now()}@test.local`, passwordHash: 'dummy', firstName: 'Admin', lastName: 'A' },
        { id: analystUserA, email: `members-analyst-a-${Date.now()}@test.local`, passwordHash: 'dummy', firstName: 'Analyst', lastName: 'A' },
        { id: noPermUserA, email: `members-noperm-a-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userB, email: `members-b-${Date.now()}@test.local`, passwordHash: 'dummy' },
      ],
    });
    await prisma.session.createMany({
      data: [
        { id: adminSessionA, userId: adminUserA, expiresAt: new Date(Date.now() + 100000) },
        { id: analystSessionA, userId: analystUserA, expiresAt: new Date(Date.now() + 100000) },
        { id: noPermSessionA, userId: noPermUserA, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionB, userId: userB, expiresAt: new Date(Date.now() + 100000) },
      ],
    });

    const adminRole = await prisma.role.create({ data: { name: 'Org Admin', organizationId: orgA } });
    const analystRole = await prisma.role.create({ data: { name: 'Analyst', organizationId: orgA } });
    const noPermRole = await prisma.role.create({ data: { name: 'No Permission', organizationId: orgA } });
    const roleBRow = await prisma.role.create({ data: { name: 'Reader B', organizationId: orgB } });
    adminRoleA = adminRole.id;
    analystRoleA = analystRole.id;
    roleB = roleBRow.id;

    await grantPermissions(adminRoleA, ['USER_READ', 'USER_MANAGE']);
    await grantPermissions(analystRoleA, ['USER_READ']);
    await grantPermissions(roleB, ['USER_READ', 'USER_MANAGE']);

    const adminMembership = await prisma.organizationMember.create({ data: { userId: adminUserA, organizationId: orgA, roleId: adminRoleA } });
    const analystMembership = await prisma.organizationMember.create({ data: { userId: analystUserA, organizationId: orgA, roleId: analystRoleA } });
    await prisma.organizationMember.create({ data: { userId: noPermUserA, organizationId: orgA, roleId: noPermRole.id } });
    await prisma.organizationMember.create({ data: { userId: userB, organizationId: orgB, roleId: roleB } });
    adminMembershipIdA = adminMembership.id;
    analystMembershipIdA = analystMembership.id;

    adminTokenA = server.jwt.sign({ sub: adminUserA, orgs: [orgA], sid: adminSessionA });
    analystTokenA = server.jwt.sign({ sub: analystUserA, orgs: [orgA], sid: analystSessionA });
    noPermTokenA = server.jwt.sign({ sub: noPermUserA, orgs: [orgA], sid: noPermSessionA });
    tokenB = server.jwt.sign({ sub: userB, orgs: [orgB], sid: sessionB });
  });

  afterAll(async () => {
    await prisma.organizationMember.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: { in: [orgA, orgB] } } } });
    await prisma.role.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.session.deleteMany({ where: { id: { in: [adminSessionA, analystSessionA, noPermSessionA, sessionB] } } });
    await prisma.user.deleteMany({ where: { email: { contains: '@test.local' }, id: { in: [adminUserA, analystUserA, noPermUserA, userB] } } });
    await prisma.user.deleteMany({ where: { email: { startsWith: 'members-new-' } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
  });

  it('lists org members with role and never leaks passwordHash', async () => {
    const res = await server.inject({
      method: 'GET', url: '/api/v1/members',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items.length).toBeGreaterThanOrEqual(3);
    expect(JSON.stringify(body)).not.toMatch(/passwordHash/i);
    const admin = body.items.find((m: any) => m.userId === adminUserA);
    expect(admin.role.name).toBe('Org Admin');
  });

  it('GET /members/roles lists org-scoped roles for the role selector', async () => {
    const res = await server.inject({
      method: 'GET', url: '/api/v1/members/roles',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.roles.some((r: any) => r.id === adminRoleA)).toBe(true);
    expect(body.roles.some((r: any) => r.id === roleB)).toBe(false);
  });

  it('supports search by email/name', async () => {
    const res = await server.inject({
      method: 'GET', url: '/api/v1/members?q=Analyst',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items.every((m: any) => m.userId === analystUserA)).toBe(true);
  });

  it('creates a new user + membership and returns a one-time temporary password', async () => {
    const email = `members-new-${Date.now()}@test.local`;
    const res = await server.inject({
      method: 'POST', url: '/api/v1/members',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email, firstName: 'New', lastName: 'Hire', roleId: analystRoleA },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.email).toBe(email.toLowerCase());
    expect(typeof body.temporaryPassword).toBe('string');
    expect(body.temporaryPassword.length).toBeGreaterThan(10);

    // Never returned again on a subsequent read
    const getRes = await server.inject({
      method: 'GET', url: `/api/v1/members/${body.id}`,
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
    });
    expect(JSON.stringify(getRes.json())).not.toContain(body.temporaryPassword);
  });

  it('a true global system role (organizationId null, isSystem true) is listed and assignable in any org — mirrors the seeded SYSTEM_ADMIN role', async () => {
    const globalRole = await prisma.role.create({ data: { name: `Global Role ${Date.now()}`, organizationId: null, isSystem: true } });

    const listRes = await server.inject({
      method: 'GET', url: '/api/v1/members/roles',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
    });
    expect(listRes.json().roles.some((r: any) => r.id === globalRole.id)).toBe(true);

    const target = await prisma.user.create({ data: { email: `members-global-${Date.now()}@test.local`, passwordHash: 'x' } });
    const membership = await prisma.organizationMember.create({ data: { userId: target.id, organizationId: orgA, roleId: analystRoleA } });
    const patchRes = await server.inject({
      method: 'PATCH', url: `/api/v1/members/${membership.id}`,
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { roleId: globalRole.id },
    });
    expect(patchRes.statusCode).toBe(200);
    expect(patchRes.json().role.id).toBe(globalRole.id);

    await prisma.organizationMember.delete({ where: { id: membership.id } });
    await prisma.user.delete({ where: { id: target.id } });
    await prisma.role.delete({ where: { id: globalRole.id } });
  });

  it('adding the same existing member twice returns 409', async () => {
    const res = await server.inject({
      method: 'POST', url: '/api/v1/members',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email: (await prisma.user.findUniqueOrThrow({ where: { id: analystUserA } })).email, roleId: analystRoleA },
    });
    expect(res.statusCode).toBe(409);
  });

  it('rejects a roleId from a different organization (privilege-escalation guard)', async () => {
    const res = await server.inject({
      method: 'POST', url: '/api/v1/members',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { email: `members-cross-${Date.now()}@test.local`, roleId: roleB },
    });
    expect(res.statusCode).toBe(400);
  });

  it('changes a member role and audits MEMBER_ROLE_CHANGED', async () => {
    const target = await prisma.user.create({ data: { email: `members-target-${Date.now()}@test.local`, passwordHash: 'x' } });
    const membership = await prisma.organizationMember.create({ data: { userId: target.id, organizationId: orgA, roleId: analystRoleA } });

    const res = await server.inject({
      method: 'PATCH', url: `/api/v1/members/${membership.id}`,
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { roleId: adminRoleA },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().role.id).toBe(adminRoleA);

    const auditRow = await prisma.auditLog.findFirst({ where: { action: 'MEMBER_ROLE_CHANGED', resourceId: membership.id }, orderBy: { createdAt: 'desc' } });
    expect(auditRow).toBeTruthy();

    await prisma.organizationMember.delete({ where: { id: membership.id } });
    await prisma.user.delete({ where: { id: target.id } });
  });

  it('deactivating a member sets User.isActive false', async () => {
    const target = await prisma.user.create({ data: { email: `members-deact-${Date.now()}@test.local`, passwordHash: 'x' } });
    const membership = await prisma.organizationMember.create({ data: { userId: target.id, organizationId: orgA, roleId: analystRoleA } });

    const res = await server.inject({
      method: 'PATCH', url: `/api/v1/members/${membership.id}`,
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { isActive: false },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().isActive).toBe(false);

    await prisma.organizationMember.delete({ where: { id: membership.id } });
    await prisma.user.delete({ where: { id: target.id } });
  });

  it('blocks removing the last active administrator', async () => {
    // adminUserA is the only member of orgA whose role grants USER_MANAGE.
    const res = await server.inject({
      method: 'DELETE', url: `/api/v1/members/${adminMembershipIdA}`,
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(409);

    const stillExists = await prisma.organizationMember.findUnique({ where: { id: adminMembershipIdA } });
    expect(stillExists).toBeTruthy();
  });

  it('blocks self-demotion that would leave the organization without an administrator', async () => {
    const res = await server.inject({
      method: 'PATCH', url: `/api/v1/members/${adminMembershipIdA}`,
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
      payload: { roleId: analystRoleA },
    });
    expect(res.statusCode).toBe(409);
  });

  it('allows removal once a second administrator exists', async () => {
    const secondAdmin = await prisma.user.create({ data: { email: `members-admin2-${Date.now()}@test.local`, passwordHash: 'x' } });
    const secondMembership = await prisma.organizationMember.create({ data: { userId: secondAdmin.id, organizationId: orgA, roleId: adminRoleA } });

    const res = await server.inject({
      method: 'DELETE', url: `/api/v1/members/${secondMembership.id}`,
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(204);

    await prisma.user.delete({ where: { id: secondAdmin.id } }).catch(() => {});
  });

  it('tenant isolation — org B cannot see or modify org A members', async () => {
    const listRes = await server.inject({
      method: 'GET', url: '/api/v1/members',
      headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
    });
    expect(listRes.json().items.find((m: any) => m.userId === adminUserA)).toBeUndefined();

    const patchRes = await server.inject({
      method: 'PATCH', url: `/api/v1/members/${analystMembershipIdA}`,
      headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      payload: { isActive: false },
    });
    expect(patchRes.statusCode).toBe(404);

    const deleteRes = await server.inject({
      method: 'DELETE', url: `/api/v1/members/${analystMembershipIdA}`,
      headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
    });
    expect(deleteRes.statusCode).toBe(404);
  });

  it('a read-only (USER_READ only) user cannot mutate members', async () => {
    const res = await server.inject({
      method: 'PATCH', url: `/api/v1/members/${analystMembershipIdA}`,
      headers: { authorization: `Bearer ${analystTokenA}`, 'x-organization-id': orgA },
      payload: { isActive: false },
    });
    expect(res.statusCode).toBe(403);
  });

  it('rejects an unauthenticated request', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/members' });
    expect(res.statusCode).toBe(401);
  });

  it('rejects a user without USER_READ permission', async () => {
    const res = await server.inject({
      method: 'GET', url: '/api/v1/members',
      headers: { authorization: `Bearer ${noPermTokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(403);
  });

  it('rejects a request with no organization context', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/members', headers: { authorization: `Bearer ${adminTokenA}` } });
    expect(res.statusCode).toBe(400);
  });

  it('rejects a malformed member id', async () => {
    const res = await server.inject({
      method: 'GET', url: '/api/v1/members/not-a-uuid',
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(400);
  });

  it('returns a safe 404 for a nonexistent member id', async () => {
    const res = await server.inject({
      method: 'GET', url: `/api/v1/members/${crypto.randomUUID()}`,
      headers: { authorization: `Bearer ${adminTokenA}`, 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(404);
  });
});
