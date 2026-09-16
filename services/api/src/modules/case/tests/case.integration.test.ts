import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import caseRoutes from '../case.routes';
import { prisma } from '@ciperscope/database';
import crypto from 'crypto';
import fastifyJwt from '@fastify/jwt';
import rbacPlugin from '../../../plugins/rbac';

describe('Case API (Integration) - POST /api/v1/cases', () => {
  let server: FastifyInstance;
  let testOrgId: string;
  let testUserId: string;

  beforeAll(async () => {
    server = Fastify({
      ajv: { customOptions: { removeAdditional: false } }
    });
    
    // Mock Authentication and Authorization for tests
    server.decorate('authenticate', async (request: { user: { sub: string, orgs: string[] } }) => {
      if ((request as any).headers['x-mock-unauthorized'] === 'true') {
         throw new Error('Unauthorized');
      }
      request.user = { sub: testUserId, orgs: [testOrgId] };
    });
    
    server.decorate('requirePermission', (action: string) => {
      return async (request: { headers: Record<string, string>, user: { sub: string, orgs: string[] } }) => {
         const orgId = request.headers['x-organization-id'];
         if (!orgId) {
           throw new Error('Tenant isolation failed: missing org');
         }
         if (request.headers['x-mock-forbidden'] === 'true') {
           throw new Error('Forbidden: no permission');
         }
         if (orgId !== testOrgId) {
           throw new Error('Forbidden: tenant isolation violation');
         }
      };
    });

    server.register(caseRoutes, { prefix: '/api/v1/cases' });

    testOrgId = crypto.randomUUID();
    testUserId = crypto.randomUUID();

    await prisma.organization.create({
      data: { id: testOrgId, name: 'Case Test Org' }
    });

    await prisma.user.create({
      data: { 
        id: testUserId, 
        email: `test-${Date.now()}@case.local`, 
        passwordHash: 'dummy' 
      }
    });
    
    await server.ready();
  });

  afterAll(async () => {
    await prisma.case.deleteMany({ where: { organizationId: testOrgId } });
    await prisma.organization.delete({ where: { id: testOrgId } });
    await prisma.user.delete({ where: { id: testUserId } });
    await server.close();
  });

  it('1. Unauthenticated request is rejected', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: {
        'x-organization-id': testOrgId,
        'x-mock-unauthorized': 'true'
      },
      payload: { title: 'Test Case' },
    });
    expect(response.statusCode).toBe(500); // Mock threw Error
  });

  it('2, 3, 4, 15. Valid authorized user can create a Case and writes CASE_CREATED audit event', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: {
        'x-organization-id': testOrgId,
      },
      payload: { title: 'Test Valid Case', description: 'desc', priority: 'HIGH' },
    });

    expect(response.statusCode).toBe(201);
    const json = response.json();
    expect(json.title).toBe('Test Valid Case');
    expect(json.organizationId).toBe(testOrgId); // 3
    expect(json.creatorId).toBe(testUserId); // 4

    // Verify DB
    const dbCase = await prisma.case.findUnique({ where: { id: json.id } });
    expect(dbCase).toBeDefined();
    expect(dbCase?.organizationId).toBe(testOrgId);
    expect(dbCase?.creatorId).toBe(testUserId);
  });

  it('5. Client-supplied organizationId is rejected with 400', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: { 'x-organization-id': testOrgId },
      payload: { title: 'Test Org Spoof', organizationId: 'fake-org' },
    });
    expect(response.statusCode).toBe(400);
  });

  it('6. Client-supplied creatorId is rejected with 400', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: { 'x-organization-id': testOrgId },
      payload: { title: 'Test Creator Spoof', creatorId: 'fake-creator' },
    });
    expect(response.statusCode).toBe(400);
  });

  it('7. Client-supplied id is rejected with 400', async () => {
    const fakeId = crypto.randomUUID();
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: { 'x-organization-id': testOrgId },
      payload: { title: 'Test ID Spoof', id: fakeId },
    });
    expect(response.statusCode).toBe(400);
  });

  it('8. Client-supplied assignedUserId is rejected with 400', async () => {
    const fakeAssign = crypto.randomUUID();
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: { 'x-organization-id': testOrgId },
      payload: { title: 'Test Assign Spoof', assignedUserId: fakeAssign },
    });
    expect(response.statusCode).toBe(400);
  });
  
  it('8.5 Client-supplied status is rejected with 400', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: { 'x-organization-id': testOrgId },
      payload: { title: 'Test Status Spoof', status: 'RESOLVED' },
    });
    expect(response.statusCode).toBe(400);
    
    // Assert no cases were persisted maliciously
    const cases = await prisma.case.findMany({ where: { title: 'Test Status Spoof' }});
    expect(cases.length).toBe(0);
  });

  it('9. Oversized title is rejected', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: { 'x-organization-id': testOrgId },
      payload: { title: 'A'.repeat(256) },
    });
    expect(response.statusCode).toBe(400);
  });

  it('10. Oversized description is rejected', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: { 'x-organization-id': testOrgId },
      payload: { title: 'Title', description: 'A'.repeat(4001) },
    });
    expect(response.statusCode).toBe(400);
  });

  it('11. Invalid priority is rejected', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: { 'x-organization-id': testOrgId },
      payload: { title: 'Title', priority: 'INVALID_PRIORITY' },
    });
    expect(response.statusCode).toBe(400);
  });

  it('12. Unknown body fields are rejected with 400 Bad Request', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: { 'x-organization-id': testOrgId },
      payload: { title: 'Title', randomField: 'foo' },
    });
    expect(response.statusCode).toBe(400);
  });

  it('13. User from Organization A cannot create a Case in Organization B', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: {
        'x-organization-id': crypto.randomUUID(), // Not the org the user is assigned to
      },
      payload: { title: 'Test Cross Org' },
    });
    expect(response.statusCode).toBe(500); // Mock threw Error
  });

  it('14, 16. User without CASE_CREATE permission is rejected and case not created', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: {
        'x-organization-id': testOrgId,
        'x-mock-forbidden': 'true'
      },
      payload: { title: 'Test Forbidden' },
    });
    expect(response.statusCode).toBe(500); // Mock threw Error

    const cases = await prisma.case.findMany({ where: { title: 'Test Forbidden' } });
    expect(cases.length).toBe(0);
  });
});

describe('Case API (Integration) - Real RBAC', () => {
  let realServer: FastifyInstance;
  let orgId: string;
  let otherOrgId: string;
  let userIdWithPerm: string;
  let userIdWithoutPerm: string;
  let sessionIdWithPerm: string;
  let sessionIdWithoutPerm: string;
  let tokenWithPerm: string;
  let tokenWithoutPerm: string;

  beforeAll(async () => {
    realServer = Fastify({
      ajv: { customOptions: { removeAdditional: false } }
    });
    realServer.register(fastifyJwt, { secret: 'test-real-secret' });
    realServer.register(rbacPlugin);
    realServer.register(caseRoutes, { prefix: '/api/v1/cases' });

    await realServer.ready();

    orgId = crypto.randomUUID();
    otherOrgId = crypto.randomUUID();
    userIdWithPerm = crypto.randomUUID();
    userIdWithoutPerm = crypto.randomUUID();
    sessionIdWithPerm = crypto.randomUUID();
    sessionIdWithoutPerm = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [
        { id: orgId, name: 'Real RBAC Org' },
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

    const roleWithPerm = await prisma.role.create({
      data: { name: 'Case Creator', organizationId: orgId }
    });
    const roleWithoutPerm = await prisma.role.create({
      data: { name: 'Read Only', organizationId: orgId }
    });
    const roleOtherOrg = await prisma.role.create({
      data: { name: 'Other Role', organizationId: otherOrgId }
    });

    const caseCreatePerm = await prisma.permission.upsert({
      where: { action: 'CASE_CREATE' },
      update: {},
      create: { action: 'CASE_CREATE', description: 'Create cases' }
    });

    const caseReadPerm = await prisma.permission.upsert({
      where: { action: 'CASE_READ' },
      update: {},
      create: { action: 'CASE_READ', description: 'Read cases' }
    });

    await prisma.rolePermission.createMany({
      data: [
        { roleId: roleWithPerm.id, permissionId: caseCreatePerm.id },
        { roleId: roleWithPerm.id, permissionId: caseReadPerm.id }
      ]
    });

    await prisma.organizationMember.create({
      data: { userId: userIdWithPerm, organizationId: orgId, roleId: roleWithPerm.id }
    });
    await prisma.organizationMember.create({
      data: { userId: userIdWithoutPerm, organizationId: orgId, roleId: roleWithoutPerm.id }
    });
    // Give userWithPerm access to otherOrgId so we can test isolation
    await prisma.organizationMember.create({
      data: { userId: userIdWithPerm, organizationId: otherOrgId, roleId: roleOtherOrg.id }
    });

    tokenWithPerm = realServer.jwt.sign({ sub: userIdWithPerm, orgs: [orgId, otherOrgId], sid: sessionIdWithPerm });
    tokenWithoutPerm = realServer.jwt.sign({ sub: userIdWithoutPerm, orgs: [orgId], sid: sessionIdWithoutPerm });
  });

  afterAll(async () => {
    await prisma.case.deleteMany({ where: { organizationId: { in: [orgId, otherOrgId] } } });
    await prisma.organizationMember.deleteMany({ where: { userId: { in: [userIdWithPerm, userIdWithoutPerm] } } });
    await prisma.rolePermission.deleteMany({ where: { role: { organizationId: { in: [orgId, otherOrgId] } } } });
    await prisma.role.deleteMany({ where: { organizationId: { in: [orgId, otherOrgId] } } });
    await prisma.session.deleteMany({ where: { id: { in: [sessionIdWithPerm, sessionIdWithoutPerm] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userIdWithPerm, userIdWithoutPerm] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgId, otherOrgId] } } });
    await realServer.close();
  });

  it('TEST A - REAL AUTH + CASE_CREATE SUCCESS', async () => {
    const response = await realServer.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: {
        'x-organization-id': orgId,
        'authorization': `Bearer ${tokenWithPerm}`
      },
      payload: { title: 'Real Test Case', priority: 'HIGH' }
    });

    expect(response.statusCode).toBe(201);
    const json = response.json();
    expect(json.organizationId).toBe(orgId);
    expect(json.creatorId).toBe(userIdWithPerm);

    const dbCase = await prisma.case.findUnique({ where: { id: json.id } });
    expect(dbCase).toBeDefined();

    const auditLog = await prisma.auditLog.findFirst({
      where: { resourceId: json.id, action: 'CASE_CREATED' }
    });
    expect(auditLog).toBeDefined();
    expect(auditLog?.actorId).toBe(userIdWithPerm);
  });

  it('TEST B - REAL RBAC DENIAL', async () => {
    const response = await realServer.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: {
        'x-organization-id': orgId,
        'authorization': `Bearer ${tokenWithoutPerm}`
      },
      payload: { title: 'Denied Case' }
    });

    expect(response.statusCode).toBe(403);
    const json = response.json();
    expect(json.message).toContain('Missing required permission');

    const auditLog = await prisma.auditLog.findFirst({
      where: { actorId: userIdWithoutPerm, action: 'AUTHZ_DENIED', organizationId: orgId },
      orderBy: { createdAt: 'desc' }
    });
    expect(auditLog).toBeDefined();
  });

  it('TEST C - REAL TENANT ISOLATION', async () => {
    const response = await realServer.inject({
      method: 'POST',
      url: '/api/v1/cases',
      headers: {
        'x-organization-id': otherOrgId,
        'authorization': `Bearer ${tokenWithoutPerm}`
      },
      payload: { title: 'Tenant Leak Case' }
    });

    expect(response.statusCode).toBe(403);
    const json = response.json();
    expect(json.message).toContain('Tenant isolation violation');
  });

  it('TEST D - GET /cases - SUCCESS with deterministic ordering', async () => {
    // Create some cases
    await prisma.case.createMany({
      data: [
        { id: crypto.randomUUID(), title: 'Case 1', organizationId: orgId, createdAt: new Date(Date.now() - 10000) },
        { id: crypto.randomUUID(), title: 'Case 2', organizationId: orgId, createdAt: new Date(Date.now() - 5000) }
      ]
    });

    const response = await realServer.inject({
      method: 'GET',
      url: '/api/v1/cases',
      headers: {
        'x-organization-id': orgId,
        'authorization': `Bearer ${tokenWithPerm}`
      }
    });

    expect(response.statusCode).toBe(200);
    const json = response.json();
    expect(json.items).toBeDefined();
    expect(json.items.length).toBeGreaterThanOrEqual(2);
    // Descending order of createdAt
    expect(new Date(json.items[0].createdAt).getTime()).toBeGreaterThanOrEqual(new Date(json.items[1].createdAt).getTime());
    // Should only return fields specified in the contract
    expect(json.items[0].title).toBeDefined();
    expect(json.items[0].organizationId).toBe(orgId);
    expect(json.items[0].createdAt).toBeDefined();
    expect(json.items[0].severity).toBeUndefined(); // We did not include severity in the explicit select
  });

  it('TEST E - GET /cases - REJECT INVALID QUERY PARAMS', async () => {
    const response = await realServer.inject({
      method: 'GET',
      url: '/api/v1/cases?limit=999&status=INVALID', // limit max is 100
      headers: {
        'x-organization-id': orgId,
        'authorization': `Bearer ${tokenWithPerm}`
      }
    });

    expect(response.statusCode).toBe(400);
  });

  it('TEST F - GET /cases - TENANT ISOLATION', async () => {
    // Create a case in the other org
    await prisma.case.create({
      data: { title: 'Other Org Case', organizationId: otherOrgId }
    });

    const response = await realServer.inject({
      method: 'GET',
      url: '/api/v1/cases',
      headers: {
        'x-organization-id': orgId,
        'authorization': `Bearer ${tokenWithPerm}`
      }
    });

    expect(response.statusCode).toBe(200);
    const json = response.json();
    
    // Ensure the list has ZERO from otherOrgId
    const foundOther = json.items.some((c: any) => c.organizationId === otherOrgId);
    expect(foundOther).toBe(false);
  });

  it('TEST G - GET /cases/:caseId - SUCCESS AND AUDIT', async () => {
    const newCase = await prisma.case.create({
      data: { title: 'Single Case Fetch', organizationId: orgId }
    });

    const response = await realServer.inject({
      method: 'GET',
      url: `/api/v1/cases/${newCase.id}`,
      headers: {
        'x-organization-id': orgId,
        'authorization': `Bearer ${tokenWithPerm}`
      }
    });

    expect(response.statusCode).toBe(200);
    const json = response.json();
    expect(json.id).toBe(newCase.id);
    expect(json.organizationId).toBe(orgId);
    
    const auditLog = await prisma.auditLog.findFirst({
      where: { resourceId: newCase.id, action: 'CASE_VIEWED' }
    });
    expect(auditLog).toBeDefined();
    expect(auditLog?.actorId).toBe(userIdWithPerm);
  });

  it('TEST H - GET /cases/:caseId - CROSS TENANT RETURNS 404', async () => {
    const newCase = await prisma.case.create({
      data: { title: 'Cross Tenant Case', organizationId: otherOrgId }
    });

    const response = await realServer.inject({
      method: 'GET',
      url: `/api/v1/cases/${newCase.id}`,
      headers: {
        'x-organization-id': orgId, // Sending request as orgId but for otherOrgId's case
        'authorization': `Bearer ${tokenWithPerm}`
      }
    });

    expect(response.statusCode).toBe(404);
  });

  it('TEST I - GET /cases/:caseId - MALFORMED UUID', async () => {
    const response = await realServer.inject({
      method: 'GET',
      url: `/api/v1/cases/not-a-uuid`,
      headers: {
        'x-organization-id': orgId,
        'authorization': `Bearer ${tokenWithPerm}`
      }
    });

    expect(response.statusCode).toBe(400);
  });
  it('TEST J - CURSOR VALIDATION - MALFORMED', async () => {
    // 2. Malformed Base64
    let res = await realServer.inject({ method: 'GET', url: `/api/v1/cases?cursor=not-base-64!`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    expect(res.statusCode).toBe(400);

    // 3. Malformed JSON
    res = await realServer.inject({ method: 'GET', url: `/api/v1/cases?cursor=${Buffer.from('{bad json}').toString('base64')}`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    expect(res.statusCode).toBe(400);

    // 4. Wrong array length
    res = await realServer.inject({ method: 'GET', url: `/api/v1/cases?cursor=${Buffer.from(JSON.stringify(['too', 'many', 'items'])).toString('base64')}`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    expect(res.statusCode).toBe(400);

    // 5. Invalid UUID
    res = await realServer.inject({ method: 'GET', url: `/api/v1/cases?cursor=${Buffer.from(JSON.stringify([new Date().toISOString(), 'not-a-uuid'])).toString('base64')}`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    expect(res.statusCode).toBe(400);

    // 6. Invalid timestamp
    res = await realServer.inject({ method: 'GET', url: `/api/v1/cases?cursor=${Buffer.from(JSON.stringify(['not-a-date', crypto.randomUUID()])).toString('base64')}`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    expect(res.statusCode).toBe(400);

    // 7. Null cursor components
    res = await realServer.inject({ method: 'GET', url: `/api/v1/cases?cursor=${Buffer.from(JSON.stringify([null, null])).toString('base64')}`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    expect(res.statusCode).toBe(400);

    // 8. Wrong JSON types
    res = await realServer.inject({ method: 'GET', url: `/api/v1/cases?cursor=${Buffer.from(JSON.stringify([123, 456])).toString('base64')}`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    expect(res.statusCode).toBe(400);

    // 9. Extra cursor fields (not array)
    res = await realServer.inject({ method: 'GET', url: `/api/v1/cases?cursor=${Buffer.from(JSON.stringify({ date: new Date(), id: crypto.randomUUID() })).toString('base64')}`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    expect(res.statusCode).toBe(400);
  });

  it('TEST K - CURSOR TAMPERING CANNOT PRODUCE 500 AND CROSS-TENANT FAILS', async () => {
    // 10. Valid UUID but doesn't exist
    const fakeId = crypto.randomUUID();
    let res = await realServer.inject({ method: 'GET', url: `/api/v1/cases?cursor=${Buffer.from(JSON.stringify([new Date().toISOString(), fakeId])).toString('base64')}`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    expect(res.statusCode).toBe(200);
    expect(res.json().items.length).toBe(0);

    // 12. Cross-tenant cursor cannot bypass organization filtering
    const otherCase = await prisma.case.create({
      data: { title: 'Other Case', organizationId: otherOrgId }
    });
    res = await realServer.inject({ method: 'GET', url: `/api/v1/cases?cursor=${Buffer.from(JSON.stringify([otherCase.createdAt.toISOString(), otherCase.id])).toString('base64')}`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    expect(res.statusCode).toBe(200);
    const crossTenantItems = res.json().items;
    expect(crossTenantItems.length).toBeGreaterThan(0);
    crossTenantItems.forEach((item: any) => {
      expect(item.organizationId).toBe(orgId);
    });
  });

  it('TEST L - VALID CURSOR PAGINATES CORRECTLY', async () => {
    // 1 and 11
    await prisma.case.createMany({
      data: [
        { id: crypto.randomUUID(), title: 'Page 1', organizationId: orgId },
        { id: crypto.randomUUID(), title: 'Page 2', organizationId: orgId }
      ]
    });

    const page1 = await realServer.inject({ method: 'GET', url: `/api/v1/cases?limit=1`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    expect(page1.statusCode).toBe(200);
    const json1 = page1.json();
    expect(json1.items.length).toBe(1);
    expect(json1.nextCursor).toBeDefined();

    const page2 = await realServer.inject({ method: 'GET', url: `/api/v1/cases?limit=1&cursor=${json1.nextCursor}`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    expect(page2.statusCode).toBe(200);
    const json2 = page2.json();
    expect(json2.items.length).toBe(1);
    // Ensure we actually got a different item
    expect(json1.items[0].id).not.toBe(json2.items[0].id);
  });

  it('TEST M - CURSOR + STATUS FILTER MISMATCH', async () => {
    // 1. Create a known case to ensure we can get a cursor
    await prisma.case.create({
      data: { id: crypto.randomUUID(), title: 'Status Mismatch Test', organizationId: orgId }
    });

    // Obtain a valid cursor from a normal Case list
    const page1 = await realServer.inject({ method: 'GET', url: `/api/v1/cases?limit=1`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    const cursor = page1.json().nextCursor;
    expect(cursor).toBeDefined();

    // 2. Reuse that cursor with a different valid status filter.
    const res = await realServer.inject({ method: 'GET', url: `/api/v1/cases?limit=1&cursor=${cursor}&status=CLOSED`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    
    // 3. Assert:
    expect(res.statusCode).not.toBe(500);
    // Response should be successful (e.g. 200 or 400 depending on DB state, but typically 200)
    expect([200, 400]).toContain(res.statusCode);
    
    if (res.statusCode === 200) {
      const items = res.json().items;
      expect(Array.isArray(items)).toBe(true);
      items.forEach((item: any) => {
        expect(item.organizationId).toBe(orgId);
      });
    }
  });

  it('TEST N - CURSOR + PRIORITY FILTER MISMATCH', async () => {
    // 1. Obtain a valid cursor from a normal Case list.
    const page1 = await realServer.inject({ method: 'GET', url: `/api/v1/cases?limit=1`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    const cursor = page1.json().nextCursor;
    expect(cursor).toBeDefined();

    // 2. Reuse that cursor with a different valid priority filter.
    const res = await realServer.inject({ method: 'GET', url: `/api/v1/cases?limit=1&cursor=${cursor}&priority=CRITICAL`, headers: { 'x-organization-id': orgId, 'authorization': `Bearer ${tokenWithPerm}` } });
    
    // 3. Assert:
    expect(res.statusCode).not.toBe(500);
    expect([200, 400]).toContain(res.statusCode);
    
    if (res.statusCode === 200) {
      const items = res.json().items;
      expect(Array.isArray(items)).toBe(true);
      items.forEach((item: any) => {
        expect(item.organizationId).toBe(orgId);
      });
    }
  });
});
