import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import caseRoutes from '../case.routes';
import { prisma } from '@ciperscope/database';
import crypto from 'crypto';
import fastifyJwt from '@fastify/jwt';
import rbacPlugin from '../../../plugins/rbac';

describe('GET /cases/:caseId/forensic-timeline (Integration)', () => {
  let server: FastifyInstance;
  let orgId: string;
  let otherOrgId: string;
  let caseId: string;
  let emailId: string;
  let userIdWithPerm: string;
  let userIdWithoutPerm: string;
  let sessionIdWithPerm: string;
  let sessionIdWithoutPerm: string;
  let tokenWithPerm: string;
  let tokenWithoutPerm: string;

  beforeAll(async () => {
    server = Fastify({ ajv: { customOptions: { removeAdditional: false } } });
    server.register(fastifyJwt, { secret: 'test-forensic-timeline-secret' });
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
        { id: orgId, name: 'Forensic Timeline Test Org' },
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

    const roleWithPerm = await prisma.role.create({ data: { name: 'Case Reader', organizationId: orgId } });
    const roleWithoutPerm = await prisma.role.create({ data: { name: 'No Access', organizationId: orgId } });

    const caseReadPerm = await prisma.permission.upsert({
      where: { action: 'CASE_READ' },
      update: {},
      create: { action: 'CASE_READ', description: 'Read cases' }
    });

    await prisma.rolePermission.create({ data: { roleId: roleWithPerm.id, permissionId: caseReadPerm.id } });

    await prisma.organizationMember.create({ data: { userId: userIdWithPerm, organizationId: orgId, roleId: roleWithPerm.id } });
    await prisma.organizationMember.create({ data: { userId: userIdWithoutPerm, organizationId: orgId, roleId: roleWithoutPerm.id } });

    tokenWithPerm = server.jwt.sign({ sub: userIdWithPerm, orgs: [orgId], sid: sessionIdWithPerm });
    tokenWithoutPerm = server.jwt.sign({ sub: userIdWithoutPerm, orgs: [orgId], sid: sessionIdWithoutPerm });

    const testCase = await prisma.case.create({
      data: { organizationId: orgId, title: 'Forensic Timeline Test Case', creatorId: userIdWithPerm }
    });
    caseId = testCase.id;

    const email = await prisma.email.create({
      data: {
        organizationId: orgId,
        caseId,
        subject: 'Test phishing email',
        senderAddress: 'attacker@evil.example',
        sha256: crypto.randomUUID().replace(/-/g, ''),
        riskScore: 42
      }
    });
    emailId = email.id;

    await prisma.riskAssessment.create({
      data: { emailId, overallScore: 91, riskLevel: 'CRITICAL', version: 'v1' }
    });
  });

  afterAll(async () => {
    await prisma.riskAssessment.deleteMany({ where: { emailId } });
    await prisma.email.deleteMany({ where: { id: emailId } });
    await prisma.case.deleteMany({ where: { id: caseId } });
    await prisma.organizationMember.deleteMany({ where: { userId: { in: [userIdWithPerm, userIdWithoutPerm] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: orgId } } });
    await prisma.role.deleteMany({ where: { organizationId: orgId } });
    await prisma.session.deleteMany({ where: { id: { in: [sessionIdWithPerm, sessionIdWithoutPerm] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userIdWithPerm, userIdWithoutPerm] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgId, otherOrgId] } } });
    await server.close();
  });

  it('returns a correlated, chronologically-real timeline for an authorized user, including a computed P1/P2/P3 priority', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/cases/${caseId}/forensic-timeline`,
      headers: { 'x-organization-id': orgId, authorization: `Bearer ${tokenWithPerm}` }
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(Array.isArray(body.items)).toBe(true);

    const caseCreated = body.items.find((e: any) => e.action === 'CASE_CREATED');
    expect(caseCreated).toBeDefined();

    const emailIngested = body.items.find((e: any) => e.action === 'EMAIL_INGESTED');
    expect(emailIngested).toBeDefined();
    expect(emailIngested.emailId).toBe(emailId);

    const threatScore = body.items.find((e: any) => e.action === 'THREAT_SCORE_CALCULATED');
    expect(threatScore).toBeDefined();
    expect(threatScore.severity).toBe('CRITICAL');
    // CRITICAL severity + score 91 (>= 90 override) must resolve to P1 via the shared calculateThreatPriority().
    expect(threatScore.priority.priority).toBe('P1');
  });

  it('denies a user in the same org without CASE_READ (403), never falling back to frontend-only trust', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/cases/${caseId}/forensic-timeline`,
      headers: { 'x-organization-id': orgId, authorization: `Bearer ${tokenWithoutPerm}` }
    });

    expect(response.statusCode).toBe(403);
  });

  it('enforces tenant isolation: a valid token cannot read another organization\'s case timeline', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/cases/${caseId}/forensic-timeline`,
      headers: { 'x-organization-id': otherOrgId, authorization: `Bearer ${tokenWithPerm}` }
    });

    expect(response.statusCode).toBe(403);
  });

  it('rejects an unauthenticated request (401)', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/cases/${caseId}/forensic-timeline`,
      headers: { 'x-organization-id': orgId }
    });

    expect(response.statusCode).toBe(401);
  });

  it('returns 404 for a case that does not exist in the caller\'s organization (not a data leak, not a 200 with empty guessed data)', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/cases/${crypto.randomUUID()}/forensic-timeline`,
      headers: { 'x-organization-id': orgId, authorization: `Bearer ${tokenWithPerm}` }
    });

    expect(response.statusCode).toBe(404);
  });
});
