import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import crypto from 'crypto';
import { prisma, SYSTEM_ENFORCED_PERMISSIONS } from '@ciperscope/database';
import rbacPlugin from '../../../plugins/rbac';
import tolerantJsonBodyParser from '../../../plugins/tolerantJsonBodyParser';
import blockchainRoutes from '../blockchain.routes';

describe('Blockchain Anchors API (Integration)', () => {
  let server: FastifyInstance;
  let orgA: string;
  let orgB: string;
  let userA: string;
  let userB: string;
  let sessionA: string;
  let sessionB: string;
  let tokenA: string;
  let tokenB: string;
  let anchorAId: string;
  let anchorBId: string;
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
    server.register(fastifyJwt, { secret: 'test-blockchain-api-secret-key-min-32-chars' });
    server.register(rbacPlugin);
    server.register(blockchainRoutes, { prefix: '/api/v1/blockchain' });
    await server.ready();

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    userA = crypto.randomUUID();
    userB = crypto.randomUUID();
    sessionA = crypto.randomUUID();
    sessionB = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [
        { id: orgA, name: 'Blockchain Org A' },
        { id: orgB, name: 'Blockchain Org B' },
      ],
    });

    const roleA = await prisma.role.create({
      data: { organizationId: orgA, name: 'Admin A' },
    });
    const roleB = await prisma.role.create({
      data: { organizationId: orgB, name: 'Admin B' },
    });

    await grantPermissions(roleA.id, ['EVIDENCE_READ', 'CASE_MANAGE_EVIDENCE']);
    await grantPermissions(roleB.id, ['EVIDENCE_READ', 'CASE_MANAGE_EVIDENCE']);

    await prisma.user.createMany({
      data: [
        { id: userA, email: `user-a-${Date.now()}@test.local`, passwordHash: 'hash' },
        { id: userB, email: `user-b-${Date.now()}@test.local`, passwordHash: 'hash' },
      ],
    });

    await prisma.organizationMember.createMany({
      data: [
        { userId: userA, organizationId: orgA, roleId: roleA.id },
        { userId: userB, organizationId: orgB, roleId: roleB.id },
      ],
    });

    await prisma.session.createMany({
      data: [
        { id: sessionA, userId: userA, expiresAt: new Date(Date.now() + 3600000) },
        { id: sessionB, userId: userB, expiresAt: new Date(Date.now() + 3600000) },
      ],
    });

    tokenA = server.jwt.sign({ sub: userA, orgs: [orgA], sid: sessionA });
    tokenB = server.jwt.sign({ sub: userB, orgs: [orgB], sid: sessionB });

    const caseA = await prisma.case.create({
      data: { organizationId: orgA, title: 'Blockchain Test Case A' },
    });
    caseAId = caseA.id;

    const evidenceA = await prisma.evidence.create({
      data: {
        organizationId: orgA,
        caseId: caseAId,
        type: 'LOG',
        storageKey: `k-${crypto.randomUUID()}`,
        sha256: crypto.randomBytes(32).toString('hex'),
        status: 'ACTIVE',
      },
    });
    evidenceAId = evidenceA.id;

    const anchorA = await prisma.blockchainAnchor.create({
      data: {
        organizationId: orgA,
        batchKey: crypto.randomBytes(32).toString('hex'),
        merkleRoot: crypto.randomBytes(32).toString('hex'),
        evidenceIds: [evidenceAId],
        evidenceCount: 1,
        status: 'BATCHED',
        network: 'sepolia',
      },
    });
    anchorAId = anchorA.id;

    await prisma.evidence.update({
      where: { id: evidenceAId },
      data: { anchorId: anchorAId },
    });

    const anchorB = await prisma.blockchainAnchor.create({
      data: {
        organizationId: orgB,
        batchKey: crypto.randomBytes(32).toString('hex'),
        merkleRoot: crypto.randomBytes(32).toString('hex'),
        evidenceIds: [],
        evidenceCount: 0,
        status: 'NOT_CONFIGURED',
      },
    });
    anchorBId = anchorB.id;
  });

  afterAll(async () => {
    await prisma.evidence.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.blockchainAnchor.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    if (caseAId) {
      await prisma.case.deleteMany({ where: { id: caseAId } });
    }
    await prisma.session.deleteMany({ where: { id: { in: [sessionA, sessionB] } } });
    await prisma.organizationMember.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: { in: [orgA, orgB] } } } });
    await prisma.role.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userA, userB] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
  });

  it('GET /anchors returns anchors scoped exclusively to requesting organization', async () => {
    const resA = await server.inject({
      method: 'GET',
      url: '/api/v1/blockchain/anchors',
      headers: {
        authorization: `Bearer ${tokenA}`,
        'x-organization-id': orgA,
      },
    });

    expect(resA.statusCode).toBe(200);
    const bodyA = JSON.parse(resA.body);
    expect(bodyA.items.length).toBe(1);
    expect(bodyA.items[0].id).toBe(anchorAId);
    expect(bodyA.items[0].organizationId).toBe(orgA);

    // Org B only sees its own anchor
    const resB = await server.inject({
      method: 'GET',
      url: '/api/v1/blockchain/anchors',
      headers: {
        authorization: `Bearer ${tokenB}`,
        'x-organization-id': orgB,
      },
    });

    expect(resB.statusCode).toBe(200);
    const bodyB = JSON.parse(resB.body);
    expect(bodyB.items.length).toBe(1);
    expect(bodyB.items[0].id).toBe(anchorBId);
    expect(bodyB.items[0].organizationId).toBe(orgB);
  });

  it('GET /anchors/:id enforces strict tenant isolation (returns 404 for cross-tenant access)', async () => {
    // User A trying to access User B's anchor
    const crossRes = await server.inject({
      method: 'GET',
      url: `/api/v1/blockchain/anchors/${anchorBId}`,
      headers: {
        authorization: `Bearer ${tokenA}`,
        'x-organization-id': orgA,
      },
    });

    expect(crossRes.statusCode).toBe(404);

    // User A accessing own anchor
    const ownRes = await server.inject({
      method: 'GET',
      url: `/api/v1/blockchain/anchors/${anchorAId}`,
      headers: {
        authorization: `Bearer ${tokenA}`,
        'x-organization-id': orgA,
      },
    });

    expect(ownRes.statusCode).toBe(200);
    const body = JSON.parse(ownRes.body);
    expect(body.id).toBe(anchorAId);
    expect(body.evidenceCount).toBe(1);
  });

  it('POST /anchors/:id/verify verifies an anchor and rejects cross-tenant requests', async () => {
    // Cross tenant
    const crossRes = await server.inject({
      method: 'POST',
      url: `/api/v1/blockchain/anchors/${anchorBId}/verify`,
      headers: {
        authorization: `Bearer ${tokenA}`,
        'x-organization-id': orgA,
      },
    });
    expect(crossRes.statusCode).toBe(404);

    // Own anchor
    const ownRes = await server.inject({
      method: 'POST',
      url: `/api/v1/blockchain/anchors/${anchorAId}/verify`,
      headers: {
        authorization: `Bearer ${tokenA}`,
        'x-organization-id': orgA,
      },
    });

    expect(ownRes.statusCode).toBe(200);
    const body = JSON.parse(ownRes.body);
    expect(body).toHaveProperty('verified');
    expect(body).toHaveProperty('localMerkleRoot');
    expect(body).toHaveProperty('network');
  });

  it('POST /anchors enqueues notarization sweep', async () => {
    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/blockchain/anchors',
      headers: {
        authorization: `Bearer ${tokenA}`,
        'x-organization-id': orgA,
      },
    });

    expect(res.statusCode).toBe(202);
    const body = JSON.parse(res.body);
    expect(body.enqueued).toBe(true);
    expect(body.message).toContain('notarization');
  });
});
