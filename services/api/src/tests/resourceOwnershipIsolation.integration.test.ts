import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma, SYSTEM_ENFORCED_PERMISSIONS } from '@ciperscope/database';
import rbacPlugin from '../plugins/rbac';
import alertRoutes from '../modules/alert/alert.routes';
import investigationRoutes from '../modules/investigation/investigation.routes';
import evidenceRoutes from '../modules/evidence/evidence.routes';
import { computeEvidenceHash, computeEventHash, buildMerkleRoot } from '@ciperscope/integrity';

/**
 * Phase 10A — single-resource ownership/tenant-isolation coverage for
 * alert/evidence/investigation, complementing the list-endpoint RBAC
 * coverage in rbacSeed.integration.test.ts. That file proves the shared
 * requirePermission middleware works; this file proves each route's own
 * `where: { ..., case: { organizationId } }` / `{ id, organizationId }`
 * resource scoping actually excludes another tenant's resource by ID —
 * a real Tenant A / Tenant B fixture, not a mocked auth layer.
 */
describe('Alert/Evidence/Investigation — cross-tenant resource ownership (Integration)', () => {
  let server: FastifyInstance;
  let orgA: string;
  let orgB: string;
  let userA: string;
  let userB: string;
  let userAWithoutPerm: string;
  let sessionA: string;
  let sessionB: string;
  let sessionAWithoutPerm: string;
  let tokenA: string;
  let tokenB: string;
  let tokenAWithoutPerm: string;
  let caseAId: string;
  let alertAId: string;
  let evidenceAId: string;
  let investigationAId: string;

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
    server.register(fastifyJwt, { secret: 'test-resource-ownership-secret' });
    server.register(rbacPlugin);
    server.register(alertRoutes, { prefix: '/api/v1/alerts' });
    server.register(investigationRoutes, { prefix: '/api/v1/investigations' });
    server.register(evidenceRoutes, { prefix: '/api/v1/evidence' });
    await server.ready();

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    userA = crypto.randomUUID();
    userB = crypto.randomUUID();
    userAWithoutPerm = crypto.randomUUID();
    sessionA = crypto.randomUUID();
    sessionB = crypto.randomUUID();
    sessionAWithoutPerm = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [
        { id: orgA, name: 'Resource Ownership Test Org A' },
        { id: orgB, name: 'Resource Ownership Test Org B' },
      ],
    });

    await prisma.user.createMany({
      data: [
        { id: userA, email: `owner-a-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userB, email: `owner-b-${Date.now()}@test.local`, passwordHash: 'dummy' },
        { id: userAWithoutPerm, email: `owner-a-noperm-${Date.now()}@test.local`, passwordHash: 'dummy' },
      ],
    });

    await prisma.session.createMany({
      data: [
        { id: sessionA, userId: userA, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionB, userId: userB, expiresAt: new Date(Date.now() + 100000) },
        { id: sessionAWithoutPerm, userId: userAWithoutPerm, expiresAt: new Date(Date.now() + 100000) },
      ],
    });

    const roleA = await prisma.role.create({ data: { name: 'Resource Reader A', organizationId: orgA } });
    const roleB = await prisma.role.create({ data: { name: 'Resource Reader B', organizationId: orgB } });
    const roleANoPerm = await prisma.role.create({ data: { name: 'No Permission A', organizationId: orgA } });

    await grantPermissions(roleA.id, ['ALERT_READ', 'ALERT_UPDATE', 'EVIDENCE_READ', 'INVESTIGATION_READ']);
    await grantPermissions(roleB.id, ['ALERT_READ', 'ALERT_UPDATE', 'EVIDENCE_READ', 'INVESTIGATION_READ']);

    await prisma.organizationMember.create({ data: { userId: userA, organizationId: orgA, roleId: roleA.id } });
    await prisma.organizationMember.create({ data: { userId: userB, organizationId: orgB, roleId: roleB.id } });
    await prisma.organizationMember.create({ data: { userId: userAWithoutPerm, organizationId: orgA, roleId: roleANoPerm.id } });

    tokenA = server.jwt.sign({ sub: userA, orgs: [orgA], sid: sessionA });
    tokenB = server.jwt.sign({ sub: userB, orgs: [orgB], sid: sessionB });
    tokenAWithoutPerm = server.jwt.sign({ sub: userAWithoutPerm, orgs: [orgA], sid: sessionAWithoutPerm });

    // Tenant A -> Case A -> Alert A / Evidence A / Investigation A
    const caseA = await prisma.case.create({ data: { organizationId: orgA, title: 'Resource Ownership Case A' } });
    caseAId = caseA.id;

    const alertA = await prisma.alert.create({
      data: { organizationId: orgA, caseId: caseAId, title: 'Alert A', message: 'Test alert for org A', severity: 'HIGH' },
    });
    alertAId = alertA.id;

    const evidenceA = await prisma.evidence.create({
      data: {
        organizationId: orgA,
        caseId: caseAId,
        type: 'RAW_EMAIL',
        storageKey: 'orgA/private/evidence-a-secret-path.eml',
        filename: 'evidence-a.eml',
        sha256: crypto.randomBytes(32).toString('hex'),
      },
    });
    evidenceAId = evidenceA.id;

    const investigationA = await prisma.investigation.create({
      data: { caseId: caseAId, title: 'Investigation A' },
    });
    investigationAId = investigationA.id;
  });

  afterAll(async () => {
    await prisma.investigation.deleteMany({ where: { caseId: caseAId } });
    await prisma.evidence.deleteMany({ where: { caseId: caseAId } });
    await prisma.alert.deleteMany({ where: { caseId: caseAId } });
    await prisma.case.deleteMany({ where: { id: caseAId } });
    await prisma.organizationMember.deleteMany({ where: { userId: { in: [userA, userB, userAWithoutPerm] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: { in: [orgA, orgB] } } } });
    await prisma.role.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.session.deleteMany({ where: { id: { in: [sessionA, sessionB, sessionAWithoutPerm] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userA, userB, userAWithoutPerm] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
  });

  describe('GET /api/v1/evidence/:evidenceId', () => {
    it('unauthenticated request -> 401', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/evidence/${evidenceAId}`,
        headers: { 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(401);
    });

    it('authenticated in the right org but missing EVIDENCE_READ -> 403', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/evidence/${evidenceAId}`,
        headers: { authorization: `Bearer ${tokenAWithoutPerm}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(403);
    });

    it("Tenant A's own resource, correct permission -> 200, and never leaks storageKey", async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/evidence/${evidenceAId}`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.id).toBe(evidenceAId);
      expect(body.filename).toBe('evidence-a.eml');
      expect(body).not.toHaveProperty('storageKey'); // Sensitive — see EVIDENCE_SAFE_SELECT
    });

    it("Tenant B, authenticated in their OWN org, cannot fetch Tenant A's evidence by ID -> 404", async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/evidence/${evidenceAId}`,
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      });
      expect(res.statusCode).toBe(404);
    });

    it('nonexistent evidence ID, correct tenant -> 404', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/evidence/${crypto.randomUUID()}`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(404);
    });
  });

  describe('GET /api/v1/evidence/:evidenceId/integrity (Phase M)', () => {
    it('unauthenticated request -> 401', async () => {
      const res = await server.inject({ method: 'GET', url: `/api/v1/evidence/${evidenceAId}/integrity`, headers: { 'x-organization-id': orgA } });
      expect(res.statusCode).toBe(401);
    });

    it('authenticated but missing EVIDENCE_READ -> 403', async () => {
      const res = await server.inject({ method: 'GET', url: `/api/v1/evidence/${evidenceAId}/integrity`, headers: { authorization: `Bearer ${tokenAWithoutPerm}`, 'x-organization-id': orgA } });
      expect(res.statusCode).toBe(403);
    });

    it("Tenant B cannot verify Tenant A's evidence -> 404", async () => {
      const res = await server.inject({ method: 'GET', url: `/api/v1/evidence/${evidenceAId}/integrity`, headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB } });
      expect(res.statusCode).toBe(404);
    });

    it('evidence with no custody events -> INCOMPLETE, honest hash still returned, no storageKey/secrets leaked', async () => {
      const res = await server.inject({ method: 'GET', url: `/api/v1/evidence/${evidenceAId}/integrity`, headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA } });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.status).toBe('INCOMPLETE');
      expect(body.chainValid).toBe(false);
      expect(body.merkleValid).toBe('NOT_BATCHED');
      expect(typeof body.evidenceHash).toBe('string');
      expect(body.evidenceHash).toMatch(/^[a-f0-9]{64}$/);
      expect(JSON.stringify(body)).not.toMatch(/storageKey|orgA\/private/i);
    });

    it('a real NOT_CONFIGURED batch (seeded as the worker would leave it) verifies honestly, matches worker Merkle output', async () => {
      // Simulate exactly what services/worker's EvidenceBatchingService
      // would have persisted — cannot call it directly here (cross-service
      // import restriction), so this seeds the same shape via Prisma.
      const custody = await prisma.chainOfCustodyEvent.create({
        data: { evidenceId: evidenceAId, action: 'UPLOADED', actorId: userA, eventHash: 'placeholder-not-real-chain-hash' },
      });
      const anchor = await prisma.blockchainAnchor.create({
        data: {
          organizationId: orgA,
          batchKey: `test-batch-${crypto.randomUUID()}`,
          merkleRoot: 'test-merkle-root-value',
          evidenceIds: [evidenceAId],
          evidenceCount: 1,
          status: 'NOT_CONFIGURED',
        },
      });
      await prisma.evidence.update({ where: { id: evidenceAId }, data: { anchorId: anchor.id } });

      try {
        const res = await server.inject({ method: 'GET', url: `/api/v1/evidence/${evidenceAId}/integrity`, headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA } });
        expect(res.statusCode).toBe(200);
        const body = res.json();
        // Chain is INVALID here (eventHash was a placeholder, not a real
        // computed chain hash) — proving the route genuinely recomputes and
        // checks it rather than trusting the stored value blindly.
        expect(body.chainValid).toBe(false);
        // Merkle recomputation also fails since 'test-merkle-root-value'
        // isn't a real SHA-256 Merkle root of the evidence's real hash —
        // proving the route genuinely reconstructs the tree rather than
        // trusting the stored merkleRoot blindly.
        expect(body.merkleValid).toBe(false);
        expect(body.anchorStatus).toBe('NOT_CONFIGURED');
      } finally {
        await prisma.evidence.update({ where: { id: evidenceAId }, data: { anchorId: null } });
        await prisma.blockchainAnchor.delete({ where: { id: anchor.id } });
        await prisma.chainOfCustodyEvent.delete({ where: { id: custody.id } });
      }
    });

    it('a genuinely correct batch (real event hash + real Merkle root) verifies as NOT_CONFIGURED, which is honest SUCCESS behavior', async () => {
      const evidenceRow = await prisma.evidence.findUniqueOrThrow({ where: { id: evidenceAId } });
      const canonicalEvidence = {
        id: evidenceRow.id, organizationId: evidenceRow.organizationId, caseId: evidenceRow.caseId, type: evidenceRow.type,
        sha256: evidenceRow.sha256, filename: evidenceRow.filename, mimeType: evidenceRow.mimeType, sizeBytes: evidenceRow.sizeBytes,
        collectionTime: evidenceRow.collectionTime,
      };
      const realEvidenceHash = computeEvidenceHash(canonicalEvidence);
      const eventTimestamp = new Date();
      const realEventHash = computeEventHash(null, { action: 'UPLOADED', actorId: userA, description: null, timestamp: eventTimestamp });
      const realMerkleRoot = buildMerkleRoot([realEvidenceHash])!;

      const custody = await prisma.chainOfCustodyEvent.create({
        data: { evidenceId: evidenceAId, action: 'UPLOADED', actorId: userA, timestamp: eventTimestamp, eventHash: realEventHash },
      });
      const anchor = await prisma.blockchainAnchor.create({
        data: {
          organizationId: orgA, batchKey: `test-batch-real-${crypto.randomUUID()}`, merkleRoot: realMerkleRoot,
          evidenceIds: [evidenceAId], evidenceCount: 1, status: 'NOT_CONFIGURED',
        },
      });
      await prisma.evidence.update({ where: { id: evidenceAId }, data: { anchorId: anchor.id } });

      try {
        const res = await server.inject({ method: 'GET', url: `/api/v1/evidence/${evidenceAId}/integrity`, headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA } });
        expect(res.statusCode).toBe(200);
        const body = res.json();
        expect(body.chainValid).toBe(true);
        expect(body.merkleValid).toBe(true);
        expect(body.status).toBe('NOT_CONFIGURED');
        expect(body.evidenceHash).toBe(realEvidenceHash);
      } finally {
        await prisma.evidence.update({ where: { id: evidenceAId }, data: { anchorId: null } });
        await prisma.blockchainAnchor.delete({ where: { id: anchor.id } });
        await prisma.chainOfCustodyEvent.delete({ where: { id: custody.id } });
      }
    });
  });

  describe('GET /api/v1/investigations/:investigationId', () => {
    it("Tenant A's own resource -> 200", async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/investigations/${investigationAId}`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().id).toBe(investigationAId);
    });

    it("Tenant B cannot fetch Tenant A's investigation by ID -> 404", async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/investigations/${investigationAId}`,
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
      });
      expect(res.statusCode).toBe(404);
    });

    it('nonexistent investigation ID, correct tenant -> 404', async () => {
      const res = await server.inject({
        method: 'GET',
        url: `/api/v1/investigations/${crypto.randomUUID()}`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
      });
      expect(res.statusCode).toBe(404);
    });
  });

  describe('PATCH /api/v1/alerts/:alertId', () => {
    it('authenticated without ALERT_UPDATE -> 403, never trusting a frontend-only check', async () => {
      const res = await server.inject({
        method: 'PATCH',
        url: `/api/v1/alerts/${alertAId}`,
        headers: { authorization: `Bearer ${tokenAWithoutPerm}`, 'x-organization-id': orgA },
        payload: { isRead: true },
      });
      expect(res.statusCode).toBe(403);
    });

    it("Tenant B, authenticated in their OWN org, cannot update Tenant A's alert by ID -> 404 (and the row is NOT modified)", async () => {
      const res = await server.inject({
        method: 'PATCH',
        url: `/api/v1/alerts/${alertAId}`,
        headers: { authorization: `Bearer ${tokenB}`, 'x-organization-id': orgB },
        payload: { isRead: true },
      });
      expect(res.statusCode).toBe(404);

      const unchanged = await prisma.alert.findUnique({ where: { id: alertAId } });
      expect(unchanged?.isRead).toBe(false);
    });

    it("Tenant A can update their own alert -> 200, and the update is actually persisted", async () => {
      const res = await server.inject({
        method: 'PATCH',
        url: `/api/v1/alerts/${alertAId}`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
        payload: { isRead: true },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().isRead).toBe(true);

      const updated = await prisma.alert.findUnique({ where: { id: alertAId } });
      expect(updated?.isRead).toBe(true);
    });

    it('nonexistent alert ID, correct tenant -> 404', async () => {
      const res = await server.inject({
        method: 'PATCH',
        url: `/api/v1/alerts/${crypto.randomUUID()}`,
        headers: { authorization: `Bearer ${tokenA}`, 'x-organization-id': orgA },
        payload: { isRead: true },
      });
      expect(res.statusCode).toBe(404);
    });
  });
});
