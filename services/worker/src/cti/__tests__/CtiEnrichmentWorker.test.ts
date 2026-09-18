import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import { CtiEnrichmentWorker } from '../CtiEnrichmentWorker';

describe('CtiEnrichmentWorker', () => {
  let mockPrisma: {
    email: { findUnique: Mock };
  };
  let enqueueIocMock: Mock;
  let worker: CtiEnrichmentWorker;

  beforeEach(() => {
    mockPrisma = {
      email: {
        findUnique: vi.fn()
      }
    };

    enqueueIocMock = vi.fn().mockResolvedValue(undefined);

    worker = new CtiEnrichmentWorker(
      mockPrisma as unknown as import('@ciperscope/database').PrismaClient,
      enqueueIocMock
    );
  });

  it('throws if email is not found', async () => {
    mockPrisma.email.findUnique.mockResolvedValue(null);
    await expect(worker.processEmail('non-existent')).rejects.toThrow(/Email non-existent not found/);
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

    await worker.processEmail('email-1');

    // 1 unique domain, 1 hash, 1 valid IP = 3 total enqueues
    expect(enqueueIocMock).toHaveBeenCalledTimes(3);

    // Ensure normalization worked
    expect(enqueueIocMock).toHaveBeenCalledWith({ type: 'DOMAIN', value: 'malicious.com' });
    expect(enqueueIocMock).toHaveBeenCalledWith({ type: 'HASH', value: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2' });
    expect(enqueueIocMock).toHaveBeenCalledWith({ type: 'IP', value: '192.168.1.1' });
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

    await worker.processEmail('email-2');

    // 50 domains + 10 IPs + 10 hashes = 70 enqueues max
    expect(enqueueIocMock).toHaveBeenCalledTimes(70);
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

    await expect(worker.processEmail('email-4')).rejects.toThrow('Simulated queue crash');
  });
});
