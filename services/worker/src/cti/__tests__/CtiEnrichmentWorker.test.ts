import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import { CtiEnrichmentWorker } from '../CtiEnrichmentWorker';

describe('CtiEnrichmentWorker', () => {
  let mockPrisma: {
    email: { findUnique: Mock };
  };
  let enqueueIocMock: Mock;
  let reevalCoordinatorMock: { initPending: Mock };
  let worker: CtiEnrichmentWorker;

  beforeEach(() => {
    mockPrisma = {
      email: {
        findUnique: vi.fn()
      }
    };

    enqueueIocMock = vi.fn().mockResolvedValue(undefined);
    reevalCoordinatorMock = { initPending: vi.fn().mockResolvedValue(undefined) };

    worker = new CtiEnrichmentWorker(
      mockPrisma as unknown as import('@ciperscope/database').PrismaClient,
      enqueueIocMock,
      reevalCoordinatorMock as unknown as import('../CtiReevaluationCoordinator').CtiReevaluationCoordinator
    );
  });

  it('throws if email is not found', async () => {
    mockPrisma.email.findUnique.mockResolvedValue(null);
    await expect(worker.processEmail('non-existent', 'org-1')).rejects.toThrow(/Email non-existent not found/);
  });

  it('processes URLs, attachments, and relay hops and enqueues them correctly', async () => {
    mockPrisma.email.findUnique.mockResolvedValue({
      id: 'email-1',
      urls: [
        { url: 'https://malicious.com/path' },
        { url: 'http://malicious.com?query=1' } // Duplicate domain
      ],
      attachments: [
        { sha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2' }
      ],
      relayHops: [
        { sourceIp: '192.168.1.1' },
        { sourceIp: 'invalid-ip' }
      ]
    });

    await worker.processEmail('email-1', 'org-1');

    // 1 unique domain, 1 hash, 1 valid IP = 3 total enqueues
    expect(enqueueIocMock).toHaveBeenCalledTimes(3);

    // Ensure normalization worked, and the originating email/org are threaded through
    expect(enqueueIocMock).toHaveBeenCalledWith({ type: 'DOMAIN', value: 'malicious.com' }, 'email-1', 'org-1');
    expect(enqueueIocMock).toHaveBeenCalledWith(
      { type: 'HASH', value: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2' },
      'email-1',
      'org-1'
    );
    expect(enqueueIocMock).toHaveBeenCalledWith({ type: 'IP', value: '192.168.1.1' }, 'email-1', 'org-1');

    // Phase 7D: the re-evaluation counter must be initialized with the exact
    // fan-out count, and before any IOC is enqueued.
    expect(reevalCoordinatorMock.initPending).toHaveBeenCalledWith('email-1', 3);
    expect(reevalCoordinatorMock.initPending.mock.invocationCallOrder[0]).toBeLessThan(
      enqueueIocMock.mock.invocationCallOrder[0]
    );
  });

  it('respects fan-out limits (50 domains, 10 IPs, 10 hashes)', async () => {
    const urls = Array.from({ length: 60 }).map((_, i) => ({ url: `https://domain${i}.com` }));
    const hops = Array.from({ length: 20 }).map((_, i) => ({ sourceIp: `10.0.0.${i}` }));
    const atts = Array.from({ length: 15 }).map((_, i) => {
      const hex = i.toString(16).padStart(2, '0');
      return { sha256: `${hex}`.padEnd(64, '0') };
    });

    mockPrisma.email.findUnique.mockResolvedValue({
      id: 'email-2',
      urls,
      relayHops: hops,
      attachments: atts
    });

    await worker.processEmail('email-2', 'org-1');

    // 50 domains + 10 IPs + 10 hashes = 70 enqueues max
    expect(enqueueIocMock).toHaveBeenCalledTimes(70);
    expect(reevalCoordinatorMock.initPending).toHaveBeenCalledWith('email-2', 70);
  });

  it('does not wait on anything when no indicators are extracted', async () => {
    mockPrisma.email.findUnique.mockResolvedValue({
      id: 'email-3',
      urls: [],
      attachments: [],
      relayHops: []
    });

    await worker.processEmail('email-3', 'org-1');

    expect(enqueueIocMock).not.toHaveBeenCalled();
    // initPending is a no-op for count 0, but still called for consistency;
    // the coordinator itself is responsible for not creating a wait when count <= 0.
    expect(reevalCoordinatorMock.initPending).toHaveBeenCalledWith('email-3', 0);
  });

  it('rejects completely if enqueue fails', async () => {
    mockPrisma.email.findUnique.mockResolvedValue({
      id: 'email-4',
      urls: [{ url: 'https://good1.com' }],
      attachments: [],
      relayHops: []
    });

    // Simulate queue failure
    enqueueIocMock.mockRejectedValueOnce(new Error('Simulated queue crash'));

    await expect(worker.processEmail('email-4', 'org-1')).rejects.toThrow('Simulated queue crash');
  });
});
