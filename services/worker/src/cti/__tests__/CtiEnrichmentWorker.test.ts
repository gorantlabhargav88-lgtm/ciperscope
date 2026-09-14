import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import { CtiEnrichmentWorker } from '../CtiEnrichmentWorker';
import { ThreatVerdict } from '@ciperscope/database';
import { NormalizedIoc } from '../IocNormalizer';

describe('CtiEnrichmentWorker', () => {
  let mockPrisma: {
    email: { findUnique: Mock };
    threatIndicator: { upsert: Mock };
    geolocationInfo: { upsert: Mock };
  };
  let mockCtiProvider: { lookup: Mock };
  let mockGeoProvider: { lookup: Mock };
  let worker: CtiEnrichmentWorker;

  beforeEach(() => {
    mockPrisma = {
      email: {
        findUnique: vi.fn()
      },
      threatIndicator: {
        upsert: vi.fn()
      },
      geolocationInfo: {
        upsert: vi.fn()
      }
    };

    mockCtiProvider = {
      lookup: vi.fn()
    };

    mockGeoProvider = {
      lookup: vi.fn()
    };

    worker = new CtiEnrichmentWorker(
      mockPrisma as unknown as import('@ciperscope/database').PrismaClient,
      mockCtiProvider as unknown as import('../providers/ReliableCtiProvider').ReliableCtiProvider,
      mockGeoProvider as unknown as import('../providers/ReliableGeoProvider').ReliableGeoProvider
    );
  });

  it('throws if email is not found', async () => {
    mockPrisma.email.findUnique.mockResolvedValue(null);
    await expect(worker.processEmail('non-existent')).rejects.toThrow(/Email non-existent not found/);
  });

  it('processes URLs, attachments, and relay hops and normalizes them correctly', async () => {
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

    mockCtiProvider.lookup.mockResolvedValue({
      status: ThreatVerdict.MALICIOUS,
      providerName: 'MockCti'
    });
    mockGeoProvider.lookup.mockResolvedValue({
      country: 'US',
      city: 'Seattle',
      providerName: 'MockGeo'
    });

    await worker.processEmail('email-1');

    // 1 unique domain, 1 hash, 1 valid IP = 3 total lookups
    expect(mockCtiProvider.lookup).toHaveBeenCalledTimes(3);

    // Ensure normalization worked
    expect(mockCtiProvider.lookup).toHaveBeenCalledWith({ type: 'DOMAIN', value: 'malicious.com' });
    expect(mockCtiProvider.lookup).toHaveBeenCalledWith({ type: 'HASH', value: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2' });
    expect(mockCtiProvider.lookup).toHaveBeenCalledWith({ type: 'IP', value: '192.168.1.1' });

    // Geo only called for the IP
    expect(mockGeoProvider.lookup).toHaveBeenCalledTimes(1);
    expect(mockGeoProvider.lookup).toHaveBeenCalledWith('192.168.1.1');

    // DB assertions
    expect(mockPrisma.threatIndicator.upsert).toHaveBeenCalledTimes(3);
    expect(mockPrisma.geolocationInfo.upsert).toHaveBeenCalledTimes(1);
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

    mockCtiProvider.lookup.mockResolvedValue(null);
    mockGeoProvider.lookup.mockResolvedValue(null);

    await worker.processEmail('email-2');

    // 50 domains + 10 IPs + 10 hashes = 70 lookups max
    expect(mockCtiProvider.lookup).toHaveBeenCalledTimes(70);
  });

  it('continues processing even if a single lookup throws a provider error', async () => {
    mockPrisma.email.findUnique.mockResolvedValue({
      id: 'email-3',
      urls: [{ url: 'https://bad.com' }, { url: 'https://good.com' }],
      attachments: [],
      relayHops: []
    });

    mockCtiProvider.lookup.mockImplementation(async (ioc: NormalizedIoc) => {
      if (ioc.value === 'bad.com') throw new Error('Simulated lookup crash');
      return { status: ThreatVerdict.CLEAN, providerName: 'Mock' };
    });

    await worker.processEmail('email-3');

    // good.com should still have been processed and saved
    expect(mockCtiProvider.lookup).toHaveBeenCalledTimes(2);
    expect(mockPrisma.threatIndicator.upsert).toHaveBeenCalledTimes(1);
    expect(mockPrisma.threatIndicator.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        create: expect.objectContaining({ iocValue: 'good.com' })
      })
    );
  });

  it('rejects completely if the database throws an error (regression)', async () => {
    mockPrisma.email.findUnique.mockResolvedValue({
      id: 'email-4',
      urls: [{ url: 'https://good1.com' }, { url: 'https://good2.com' }],
      attachments: [],
      relayHops: []
    });

    mockCtiProvider.lookup.mockResolvedValue({
      status: ThreatVerdict.CLEAN,
      providerName: 'MockCti'
    });

    // Simulate Prisma throwing on the first upsert
    mockPrisma.threatIndicator.upsert.mockRejectedValueOnce(new Error('Simulated database crash'));

    await expect(worker.processEmail('email-4')).rejects.toThrow('Simulated database crash');

    // Good2.com might or might not have been processed due to Promise.all,
    // but the critical requirement is that processEmail REJECTS so the job fails.
  });
});
