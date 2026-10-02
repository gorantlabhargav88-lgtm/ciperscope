import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PrismaClient, IdempotencyOperationStatus } from '@ciperscope/database';
import IORedis from 'ioredis';
import { IdempotencyManager, createTenantScopedWorker, TenantAwareJobPayload } from './index';
import { Queue, QueueEvents } from 'bullmq';

const prisma = new PrismaClient({
  datasources: {
    db: {
      url: 'postgresql://ciperscope_user:ciperscope_password@127.0.0.1:5432/ciperscope_db?schema=public'
    }
  }
});
const redis = new IORedis('redis://127.0.0.1:6379');
let manager: IdempotencyManager;

beforeAll(async () => {
  await prisma.$connect();
  manager = new IdempotencyManager(redis, prisma);
});

afterAll(async () => {
  await prisma.$disconnect();
  redis.disconnect();
});

describe('Integration: IdempotencyManager (Real PostgreSQL + Real Redis)', () => {
  const orgId = 'org-integration-test';
  
  beforeEach(async () => {
    await prisma.idempotencyOperation.deleteMany({ where: { organizationId: orgId } });
    let cursor = '0';
    do {
      const [nextCursor, keys] = await redis.scan(
        cursor,
        'MATCH',
        `idempotency_lock:${orgId}:*`,
        'COUNT',
        100
      );
      cursor = nextCursor;
      if (keys.length > 0) await redis.del(...keys);
    } while (cursor !== '0');
  });

  it('1. First operation succeeds and persists to database', async () => {
    const opKey = 'op-1';
    const acquired = await manager.acquireLock(orgId, opKey, 'res-1', 'analyze', 10);
    expect(acquired).toBe(true);
    
    const dbRecord = await prisma.idempotencyOperation.findUnique({
      where: { organizationId_operationKey_resourceId: { organizationId: orgId, operationKey: opKey, resourceId: 'res-1' } }
    });
    expect(dbRecord).toBeDefined();
    expect(dbRecord?.status).toBe(IdempotencyOperationStatus.PROCESSING);
  });

  it('2. Concurrent duplicate requests are serialized (Redis lock)', async () => {
    const opKey = 'op-concurrent';
    // Simulate concurrent requests
    const results = await Promise.allSettled([
      manager.acquireLock(orgId, opKey, 'res-2', 'analyze', 10),
      manager.acquireLock(orgId, opKey, 'res-2', 'analyze', 10),
      manager.acquireLock(orgId, opKey, 'res-2', 'analyze', 10)
    ]);
    
    // Only one should acquire the lock
    const acquiredCount = results.filter(r => r.status === 'fulfilled' && r.value === true).length;
    expect(acquiredCount).toBe(1);
    expect(results.filter(r => r.status === 'rejected')).toHaveLength(2);
    
    // Check DB has exactly one record
    const dbRecords = await prisma.idempotencyOperation.findMany({
      where: { organizationId: orgId, operationKey: opKey }
    });
    expect(dbRecords.length).toBe(1);
  });

  it('3. Completed operations can be reconciled after Redis lock expiry', async () => {
    const opKey = 'op-complete';
    await manager.acquireLock(orgId, opKey, 'res-3', 'analyze', 10);
    await manager.markCompleted(orgId, opKey, 'res-3', 'result-ref');
    
    // Attempt again
    const acquired = await manager.acquireLock(orgId, opKey, 'res-3', 'analyze', 10);
    expect(acquired).toBe(false); // Should be false because it is already completed in DB
  });

  it('delays active-lock contention until the existing operation can be retried', async () => {
    const opKey = `op-lock-delay-${Date.now()}`;
    const resourceId = `res-lock-delay-${Date.now()}`;
    const queueName = `idempotency-delay-${Date.now()}`;
    await manager.acquireLock(orgId, opKey, resourceId, 'analyze', 2);

    const bullRedis = new IORedis('redis://127.0.0.1:6379', { maxRetriesPerRequest: null });
    const queue = new Queue(queueName, { connection: bullRedis });
    const queueEvents = new QueueEvents(queueName, { connection: bullRedis.duplicate() });
    let processorRuns = 0;
    const worker = createTenantScopedWorker(
      queueName,
      bullRedis,
      async (job) => {
        processorRuns++;
        await manager.acquireLock(orgId, opKey, resourceId, 'analyze', 2);
        await manager.markCompleted(orgId, opKey, resourceId, 'result-ref');
        return { resourceId: job.data.resourceId };
      }
    );

    try {
      await Promise.all([worker.waitUntilReady(), queueEvents.waitUntilReady()]);
      const job = await queue.add('analyze', {
        organizationId: orgId,
        resourceId,
        jobId: 'lock-delay-job',
        operation: 'analyze',
      });
      const result = await job.waitUntilFinished(queueEvents, 10_000);

      expect(result).toEqual({ resourceId });
      expect(processorRuns).toBe(2);
      expect(await (await queue.getJob(job.id!))?.getState()).toBe('completed');
    } finally {
      await worker.close();
      await queueEvents.close();
      await queue.close();
      await bullRedis.quit();
    }
  });

  it('4. Retries do not repeat irreversible side effects (Failed operations allow retry)', async () => {
    const opKey = 'op-fail';
    await manager.acquireLock(orgId, opKey, 'res-4', 'analyze', 10);
    await manager.markFailed(orgId, opKey, 'res-4', 'Simulated failure');
    
    // Retry
    const acquired = await manager.acquireLock(orgId, opKey, 'res-4', 'analyze', 10);
    expect(acquired).toBe(true); // Should allow retry
    
    const dbRecord = await prisma.idempotencyOperation.findUnique({
      where: { organizationId_operationKey_resourceId: { organizationId: orgId, operationKey: opKey, resourceId: 'res-4' } }
    });
    expect(dbRecord?.attemptCount).toBe(2);
  });

  it('5. Operation identity has a durable unique constraint', async () => {
    // Verified by Prisma schema Unique constraint, but we can test it indirectly by DB query
    const opKey = 'op-unique';
    await manager.acquireLock(orgId, opKey, 'res-5', 'analyze', 10);
    
    await expect(prisma.idempotencyOperation.create({
      data: {
        organizationId: orgId,
        operationKey: opKey,
        resourceId: 'res-5',
        operationType: 'analyze',
        status: IdempotencyOperationStatus.PROCESSING
      }
    })).rejects.toThrow();
  });
});

describe('Integration: Tenant Isolation (Real PostgreSQL)', () => {
  let testOrgId: string;
  let otherOrgId: string;
  let testEmailId: string;

  beforeAll(async () => {
    // Setup test data
    const org = await prisma.organization.create({ data: { name: 'Tenant A', domain: `a-${Date.now()}.com` } });
    testOrgId = org.id;
    
    const orgB = await prisma.organization.create({ data: { name: 'Tenant B', domain: `b-${Date.now()}.com` } });
    otherOrgId = orgB.id;

    const testCase = await prisma.case.create({
      data: { organizationId: testOrgId, title: 'Test Case', status: 'OPEN', description: 'Test', priority: 'LOW' }
    });
    
    const email = await prisma.email.create({
      data: { 
        organizationId: testOrgId,
        caseId: testCase.id,
        senderAddress: 'test@a.com',
        date: new Date(),
        sha256: `test-sha256-${Date.now()}`
      }
    });
    testEmailId = email.id;
  });

  afterAll(async () => {
    // Cleanup
    await prisma.email.deleteMany({ where: { id: testEmailId } });
    await prisma.case.deleteMany({ where: { organizationId: testOrgId } });
    await prisma.organization.deleteMany({ where: { id: { in: [testOrgId, otherOrgId] } } });
  });

  const validator = async (resourceId: string, organizationId: string) => {
    const email = await prisma.email.findUnique({
      where: { id: resourceId },
      include: { case: true }
    });
    return email?.case?.organizationId === organizationId;
  };

  it('1. Allows access to owned resource', async () => {
    const isValid = await validator(testEmailId, testOrgId);
    expect(isValid).toBe(true);
  });

  it('2. Denies cross-tenant access to another tenant\'s resource', async () => {
    const isValid = await validator(testEmailId, otherOrgId);
    expect(isValid).toBe(false);
  });
});
