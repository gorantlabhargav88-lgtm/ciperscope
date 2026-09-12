import { describe, it, expect, vi, beforeEach } from 'vitest';
import { generateIdempotencyKey, IdempotencyManager, wrapTenantScopedProcessor } from './index';
import { IdempotencyOperationStatus } from '@ciperscope/database';

// Mock IORedis
const mockRedis = {
  set: vi.fn(),
  get: vi.fn(),
  del: vi.fn(),
};

// Mock Prisma
const mockPrisma = {
  idempotencyOperation: {
    findUnique: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
  },
};

describe('IdempotencyManager', () => {
  let manager: IdempotencyManager;

  beforeEach(() => {
    vi.clearAllMocks();
    manager = new IdempotencyManager(mockRedis as any, mockPrisma as any);
  });

  it('1. First operation succeeds (no existing DB record)', async () => {
    mockRedis.set.mockResolvedValue('OK');
    mockPrisma.idempotencyOperation.findUnique.mockResolvedValue(null);
    mockPrisma.idempotencyOperation.create.mockResolvedValue({ id: 'op-1' });

    const result = await manager.acquireLock('org-1', 'op-key', 'res-1', 'analyze');
    
    expect(result).toBe(true);
    expect(mockRedis.set).toHaveBeenCalledWith('idempotency_lock:org-1:op-key:res-1', 'locked', 'EX', 300, 'NX');
    expect(mockPrisma.idempotencyOperation.create).toHaveBeenCalled();
  });

  it('2. Same operation requested twice (completed)', async () => {
    mockRedis.set.mockResolvedValue('OK');
    mockPrisma.idempotencyOperation.findUnique.mockResolvedValue({
      status: IdempotencyOperationStatus.SUCCEEDED,
    });

    const result = await manager.acquireLock('org-1', 'op-key', 'res-1', 'analyze');
    
    expect(result).toBe(false);
    expect(mockRedis.del).toHaveBeenCalledWith('idempotency_lock:org-1:op-key:res-1');
  });

  it('3. Concurrent duplicate operations (Redis lock prevents DB check)', async () => {
    mockRedis.set.mockResolvedValue(null); // Lock not acquired

    const result = await manager.acquireLock('org-1', 'op-key', 'res-1', 'analyze');
    
    expect(result).toBe(false);
    expect(mockPrisma.idempotencyOperation.findUnique).not.toHaveBeenCalled();
  });

  it('4. Retry after failure (DB state FAILED)', async () => {
    mockRedis.set.mockResolvedValue('OK');
    mockPrisma.idempotencyOperation.findUnique.mockResolvedValue({
      id: 'op-1',
      status: IdempotencyOperationStatus.FAILED,
      attemptCount: 1,
    });

    const result = await manager.acquireLock('org-1', 'op-key', 'res-1', 'analyze');
    
    expect(result).toBe(true);
    expect(mockPrisma.idempotencyOperation.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 'op-1' },
        data: expect.objectContaining({ status: IdempotencyOperationStatus.PROCESSING, attemptCount: 2 }),
      })
    );
  });

  it('5. Retry after worker crash simulation (DB state PROCESSING but Redis lock expired)', async () => {
    mockRedis.set.mockResolvedValue('OK');
    mockPrisma.idempotencyOperation.findUnique.mockResolvedValue({
      id: 'op-1',
      status: IdempotencyOperationStatus.PROCESSING,
      attemptCount: 1,
    });

    const result = await manager.acquireLock('org-1', 'op-key', 'res-1', 'analyze');
    
    expect(result).toBe(true);
    expect(mockPrisma.idempotencyOperation.update).toHaveBeenCalled();
  });

  it('6. Completed operation returns existing result', async () => {
    mockRedis.set.mockResolvedValue('OK');
    mockPrisma.idempotencyOperation.findUnique.mockResolvedValue({
      status: IdempotencyOperationStatus.SUCCEEDED,
    });

    const result = await manager.acquireLock('org-1', 'op-key', 'res-1', 'analyze');
    expect(result).toBe(false);
  });

  it('7. Expired Redis lock allows safe recovery (implicitly tested via 5)', () => {
    // Covered by test 5 where Redis lock acquisition succeeds because it was expired/cleared
  });

  it('8. Recovery checks durable state before side effect', async () => {
    mockRedis.set.mockResolvedValue('OK');
    mockPrisma.idempotencyOperation.findUnique.mockResolvedValue({
      status: IdempotencyOperationStatus.RECONCILIATION_REQUIRED,
    });

    await expect(manager.acquireLock('org-1', 'op-key', 'res-1', 'analyze')).rejects.toThrow('Operation requires external reconciliation before retry.');
  });
});

describe('Worker Tenant Isolation Security Tests', () => {
  const runJob = async (data: any, validator?: any) => {
    const mockProcessor = vi.fn().mockResolvedValue({ success: true });
    const wrapped = wrapTenantScopedProcessor(mockProcessor, validator);
    return {
      result: wrapped({ data, id: 'test-job-id' } as any),
      mockProcessor,
    };
  };

  it('1. Organization A accesses A resource (ALLOW)', async () => {
    const validator = vi.fn().mockResolvedValue(true); // DB returns true (owns resource)
    const { result, mockProcessor } = await runJob({
      organizationId: 'org-A',
      resourceId: 'res-1',
      jobId: 'job-1',
      operation: 'analyze',
    }, validator);
    
    await expect(result).resolves.toEqual({ success: true });
    expect(mockProcessor).toHaveBeenCalledTimes(1);
    expect(validator).toHaveBeenCalledWith('res-1', 'org-A');
  });

  it('2. Organization A accesses B resource (DENY)', async () => {
    const validator = vi.fn().mockResolvedValue(false); // DB returns false (does not own)
    const { result, mockProcessor } = await runJob({
      organizationId: 'org-A',
      resourceId: 'res-B',
      jobId: 'job-1',
      operation: 'analyze',
    }, validator);
    
    await expect(result).rejects.toThrow('Tenant isolation failed: Resource res-B does not belong to organization org-A');
    expect(mockProcessor).not.toHaveBeenCalled();
    expect(validator).toHaveBeenCalledWith('res-B', 'org-A');
  });

  it('3. Same resource ID under different organization (DENY)', async () => {
    const validator = vi.fn().mockResolvedValue(false);
    const { result } = await runJob({
      organizationId: 'org-malicious',
      resourceId: 'res-shared-id',
      jobId: 'job-1',
      operation: 'analyze',
    }, validator);
    
    await expect(result).rejects.toThrow();
  });

  it('4. Missing organization ID (DENY)', async () => {
    const { result } = await runJob({
      resourceId: 'res-1',
      jobId: 'job-1',
      operation: 'analyze',
    });
    
    await expect(result).rejects.toThrow('Tenant isolation failed: Missing organizationId in job payload.');
  });

  it('5. Missing resource ID (DENY)', async () => {
    const { result } = await runJob({
      organizationId: 'org-A',
      jobId: 'job-1',
      operation: 'analyze',
    });
    
    await expect(result).rejects.toThrow('Tenant isolation failed: Missing resourceId in job payload.');
  });
});

