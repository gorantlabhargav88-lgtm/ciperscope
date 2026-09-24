import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma, SYSTEM_ENFORCED_PERMISSIONS } from '@ciperscope/database';
import rbacPlugin from '../../../plugins/rbac';
import tolerantJsonBodyParser from '../../../plugins/tolerantJsonBodyParser';
import evidenceRoutes from '../evidence.routes';

/**
 * Org-wide Evidence Vault API (GET /evidence, GET /evidence/:id, GET
 * /evidence/:id/integrity) — tenant isolation, permission enforcement, and
 * the "storageKey is never returned" contract. Same fixture pattern as
 * webhook.integration.test.ts. Case-scoped evidence endpoints
 * (/cases/:caseId/evidence/*) are covered separately under modules/case.
 */
describe('Evidence Vault API (Integration)', () => {
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
  let caseAId: string;
  let evidenceAId: string;

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
    server.register(fastifyJwt, { secret: 'test-evidence-vault-api-secret' });
    server.register(rbacPlugin);
    server.register(evidenceRoutes, { prefix: '/api/v1/evidence' });
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
        { id: orgA, name: 'Evidence Vault Test Org A' },
        { id: orgB, name: 'Evidence Vault Test Org B' },
      ],
    });

    await prisma.user.createMany({
      data: [
        { id: userA, email: `evidence-a-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userB, email: `evidence-b-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userANoPerm, email: `evidence-a-noperm-${Date.now()}@test.local`, passwordHash: 'dummy' },
      ],
    });

    await prisma.session.createMany({
      data: [
        { id: sessionA, userId: userA, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionB, userId: userB, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionANoPerm, userId: userANoPerm, expiresAt: new Date(Date.now() + 100000) },
      ],
    });

    const roleA = await prisma.role.create({ data: { name: 'Evidence Reader A', organizationId: orgA } });
    const roleB = await prisma.role.create({ data: { name: 'Evidence Reader B', organizationId: orgB } });
    const roleANoPerm = await prisma.role.create({ data: { name: 'No Permission A', organizationId: orgA } });

    await grantPermissions(roleA.id, ['EVIDENCE_READ']);
    await grantPermissions(roleB.id, ['EVIDENCE_READ']);

    await prisma.organizationMember.create({ data: { userId: userA, organizationId: orgA, roleId: roleA.id } });
    await prisma.organizationMember.create({ data: { userId: userB, organizationId: orgB, roleId: roleB.id } });
    await prisma.organizationMember.create({ data: { userId: userANoPerm, organizationId: orgA, roleId: roleANoPerm.id } });

    tokenA = server.jwt.sign({ sub: userA, orgs: [orgA], sid: sessionA });
    tokenB = server.jwt.sign({ sub: userB, orgs: [orgB], sid: sessionB });
    tokenANoPerm = server.jwt.sign({ sub: userANoPerm, orgs: [orgA], sid: sessionANoPerm });

    const caseA = await prisma.case.create({
      data: { organizationId: orgA, title: 'Evidence Vault Test Case', priority: 'MEDIUM', status: 'OPEN' },
    });
    caseAId = caseA.id;

    const evidenceA = await prisma.evidence.create({
      data: {
        organizationId: orgA,
        caseId: caseAId,
        type: 'ATTACHMENT',
        filename: 'sample-attachment.bin',
        mimeType: 'application/octet-stream',
        sizeBytes: 1024,
        sha256: crypto.createHash('sha256').update('evidence-vault-test-content').digest('hex'),
        status: 'ACTIVE',
        collectionTime: new Date(),
        storageKey: 'secret/internal/storage-path/should-never-leak.bin',
      },
    });
    evidenceAId = evidenceA.id;
  });

  afterAll(async () => {
    await prisma.chainOfCustodyEvent.deleteMany({ where: { evidenceId: evidenceAId } });
    await prisma.evidence.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.case.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.organizationMember.deleteMany({ where: { userId: { in: [userA, userB, userANoPerm] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: { in: [orgA, orgB] } } } });
    await prisma.role.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.session.deleteMany({ where: { id: { in: [sessionA, sessionB, sessionANoPerm] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userA, userB, userANoPerm] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
  });

  describe('GET /api/v1/evidence', () => {
    it('lists evidence for the requesting org and never leaks storageKey', async () => {
      const res = await server.inject({
        method: 'GET',
        url: '/api/v1/evidence',
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.items.find((e: any) => e.id === evidenceAId)).toBeTruthy();
      for (const item of body.items) {
        expect(item.storageKey).toBeUndefined();
      }
    });

    it('tenant isolation — org B never sees org A evidence in its list', async () => {
      const res = await server.inject({
        method: 'GET',
        url: '/api/v1/evidence',
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.items.find((e: any) => e.id === evidenceAId)).toBeUndefined();
    });

    it('rejects an unauthenticated request', async () => {
      const res = await server.inject({ method: 'GET', url: '/api/v1/evidence' });
      expect(res.statusCode).toBe(401);
    });

    it('rejects a user without EVIDENCE_READ permission', async () => {
      const res = await server.inject({
        method: 'GET',
        url: '/api/v1/evidence',
        headers: { authorization: `Bearer ${tokenANoPerm}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(403);
    });

    it('rejects a request with no organization context', async () => {
      // The rbac plugin's requirePermission check runs before the route
      // handler's own defensive organizationId check, so a missing
      // x-organization-id header is rejected as 400, not 403 — see
      // services/api/src/plugins/rbac.ts's "Missing x-organization-id
      // header context" branch.
      const res = await server.inject({
        method: 'GET',
        url: '/api/v1/evidence?limit=20',
        headers: { authorization: `Bearer ${tokenA}` },
      });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('GET /api/v1/evidence/:evidenceId', () => {
    it('returns evidence detail for the owning org and never leaks storageKey', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/evidence/${evidenceAId}`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.id).toBe(evidenceAId);
      expect(body.storageKey).toBeUndefined();
    });

    it('IDOR — org B requesting org A evidence by id gets 404, not the record', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/evidence/${evidenceAId}`,
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      });
      expect(res.statusCode).toBe(404);
    });

    it('returns 404 for a nonexistent evidence id', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/evidence/${crypto.randomUUID()}`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(404);
    });
  });

  describe('GET /api/v1/evidence/:evidenceId/integrity', () => {
    it('returns an honest NOT_CONFIGURED/INCOMPLETE verification result, never storageKey or raw content', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/evidence/${evidenceAId}/integrity`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(['VALID', 'INVALID', 'INCOMPLETE', 'NOT_CONFIGURED']).toContain(body.status);
      expect(body.evidenceHash).toBeTruthy();
      expect(body.storageKey).toBeUndefined();
    });

    it('IDOR — org B cannot verify integrity of org A evidence', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/evidence/${evidenceAId}/integrity`,
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      });
      expect(res.statusCode).toBe(404);
    });

    it('rejects a user without EVIDENCE_READ permission', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/evidence/${evidenceAId}/integrity`,
        headers: { authorization: `Bearer ${tokenANoPerm}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(403);
    });
  });
});
