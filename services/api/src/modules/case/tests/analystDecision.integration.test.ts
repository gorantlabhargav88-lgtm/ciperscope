import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import caseRoutes from '../case.routes';
import { prisma } from '@ciperscope/database';
import crypto from 'crypto';
import fastifyJwt from '@fastify/jwt';
import rbacPlugin from '../../../plugins/rbac';

/**
 * Extends the existing coverage in case.integration.test.ts (which tests
 * the 201/200 happy path with mocked auth) with REAL RBAC/tenant-isolation
 * enforcement and request-validation edge cases for
 * POST /cases/:caseId/investigations/:investigationId/decisions — needed
 * for Phase 6's analyst action layer, which now calls this endpoint
 * directly from the timeline UI.
 */
describe('POST /cases/:caseId/investigations/:investigationId/decisions — real RBAC (Integration)', () => {
  let server: FastifyInstance;
  let orgId: string;
  let otherOrgId: string;
  let caseId: string;
  let investigationId: string;
  let userIdWithPerm: string;
  let userIdWithoutPerm: string;
  let sessionIdWithPerm: string;
  let sessionIdWithoutPerm: string;
  let tokenWithPerm: string;
  let tokenWithoutPerm: string;

  beforeAll(async () => {
    server = Fastify({ ajv: { customOptions: { removeAdditional: false } } });
    server.register(fastifyJwt, { secret: 'test-analyst-decision-secret' });
    server.register(rbacPlugin);
    server.register(caseRoutes, { prefix: '/api/v1/cases' });
    await server.ready();

    orgId = crypto.randomUUID();
    otherOrgId = crypto.randomUUID();
    userIdWithPerm = crypto.randomUUID();
    userIdWithoutPerm = crypto.randomUUID();
    sessionIdWithPerm = crypto.randomUUID();
    sessionIdWithoutPerm = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [
        { id: orgId, name: 'Analyst Decision Test Org' },
        { id: otherOrgId, name: 'Other Org' }
      ]
    });

    await prisma.user.createMany({
      data: [
        { id: userIdWithPerm, email: `with-perm-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userIdWithoutPerm, email: `no-perm-${Date.now()}@test.local`, passwordHash: 'dummy' }
      ]
    });

    await prisma.session.createMany({
      data: [
        { id: sessionIdWithPerm, userId: userIdWithPerm, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionIdWithoutPerm, userId: userIdWithoutPerm, expiresAt: new Date(Date.now() + 100000) }
      ]
    });

    const roleWithPerm = await prisma.role.create({ data: { name: 'Case Updater', organizationId: orgId } });
    const roleWithoutPerm = await prisma.role.create({ data: { name: 'Read Only', organizationId: orgId } });

    const caseUpdatePerm = await prisma.permission.upsert({
      where: { action: 'CASE_UPDATE' },
      update: {},
      create: { action: 'CASE_UPDATE', description: 'Update cases' }
    });

    await prisma.rolePermission.create({ data: { roleId: roleWithPerm.id, permissionId: caseUpdatePerm.id } });

    await prisma.organizationMember.create({ data: { userId: userIdWithPerm, organizationId: orgId, roleId: roleWithPerm.id } });
    await prisma.organizationMember.create({ data: { userId: userIdWithoutPerm, organizationId: orgId, roleId: roleWithoutPerm.id } });

    tokenWithPerm = server.jwt.sign({ sub: userIdWithPerm, orgs: [orgId], sid: sessionIdWithPerm });
    tokenWithoutPerm = server.jwt.sign({ sub: userIdWithoutPerm, orgs: [orgId], sid: sessionIdWithoutPerm });

    const testCase = await prisma.case.create({ data: { organizationId: orgId, title: 'Analyst Decision Test Case' } });
    caseId = testCase.id;
    const investigation = await prisma.investigation.create({ data: { caseId, title: 'Test Investigation' } });
    investigationId = investigation.id;
  });

  afterAll(async () => {
    await prisma.auditLog.deleteMany({ where: { organizationId: orgId, resourceId: investigationId } });
    await prisma.investigation.deleteMany({ where: { id: investigationId } });
    await prisma.case.deleteMany({ where: { id: caseId } });
    await prisma.organizationMember.deleteMany({ where: { userId: { in: [userIdWithPerm, userIdWithoutPerm] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: orgId } } });
    await prisma.role.deleteMany({ where: { organizationId: orgId } });
    await prisma.session.deleteMany({ where: { id: { in: [sessionIdWithPerm, sessionIdWithoutPerm] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userIdWithPerm, userIdWithoutPerm] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgId, otherOrgId] } } });
    await server.close();
  });

  it('records a real decision for an authorized user with CASE_UPDATE', async () => {
    const response = await server.inject({
      method: 'POST',
      url: `/api/v1/cases/${caseId}/investigations/${investigationId}/decisions`,
      headers: { 'x-organization-id': orgId, authorization: `Bearer ${tokenWithPerm}` },
      payload: { targetId: 'email-abc', targetType: 'Email', decision: 'CONFIRMED', reason: 'Confirmed via live test' }
    });
    expect(response.statusCode).toBe(201);
    expect(response.json().decision).toBe('CONFIRMED');
  });

  it('rejects an unauthenticated request (401)', async () => {
    const response = await server.inject({
      method: 'POST',
      url: `/api/v1/cases/${caseId}/investigations/${investigationId}/decisions`,
      headers: { 'x-organization-id': orgId },
      payload: { targetId: 'email-abc', targetType: 'Email', decision: 'CONFIRMED' }
    });
    expect(response.statusCode).toBe(401);
  });

  it('denies a user without CASE_UPDATE (403), never trusting a frontend-only check', async () => {
    const response = await server.inject({
      method: 'POST',
      url: `/api/v1/cases/${caseId}/investigations/${investigationId}/decisions`,
      headers: { 'x-organization-id': orgId, authorization: `Bearer ${tokenWithoutPerm}` },
      payload: { targetId: 'email-abc', targetType: 'Email', decision: 'CONFIRMED' }
    });
    expect(response.statusCode).toBe(403);
  });

  it('enforces tenant isolation: a token not claiming membership in the target org is rejected before the investigation is even looked up', async () => {
    const response = await server.inject({
      method: 'POST',
      url: `/api/v1/cases/${caseId}/investigations/${investigationId}/decisions`,
      headers: { 'x-organization-id': otherOrgId, authorization: `Bearer ${tokenWithPerm}` },
      payload: { targetId: 'email-abc', targetType: 'Email', decision: 'CONFIRMED' }
    });
    expect(response.statusCode).toBe(403);
  });

  it('rejects an unsupported decision value (schema validation, not a fabricated action)', async () => {
    const response = await server.inject({
      method: 'POST',
      url: `/api/v1/cases/${caseId}/investigations/${investigationId}/decisions`,
      headers: { 'x-organization-id': orgId, authorization: `Bearer ${tokenWithPerm}` },
      payload: { targetId: 'email-abc', targetType: 'Email', decision: 'APPROVED' }
    });
    expect(response.statusCode).toBe(400);
  });

  it('returns 404 for a nonexistent investigation rather than silently recording against nothing', async () => {
    const response = await server.inject({
      method: 'POST',
      url: `/api/v1/cases/${caseId}/investigations/${crypto.randomUUID()}/decisions`,
      headers: { 'x-organization-id': orgId, authorization: `Bearer ${tokenWithPerm}` },
      payload: { targetId: 'email-abc', targetType: 'Email', decision: 'CONFIRMED' }
    });
    expect(response.statusCode).toBe(404);
  });
});
