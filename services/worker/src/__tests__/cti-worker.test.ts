import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockPrismaInstance, mockCtiProvider, mockGeoProvider } = vi.hoisted(() => {
  return {
    mockPrismaInstance: {
      indicator: { findUnique: vi.fn(), create: vi.fn() },
      threatIntelObservation: { findFirst: vi.fn(), create: vi.fn(), update: vi.fn() },
      geoLocation: { upsert: vi.fn() },
      $disconnect: vi.fn(),
    },
    mockCtiProvider: { enrichIp: vi.fn(), enrichDomain: vi.fn(), enrichHash: vi.fn() },
    mockGeoProvider: { lookup: vi.fn() },
  };
});

vi.mock('@ciperscope/database', () => ({
  PrismaClient: vi.fn(() => mockPrismaInstance),
  IndicatorType: { IP: 'IP', DOMAIN: 'DOMAIN', HASH: 'HASH' },
}));

vi.mock('@ciperscope/providers', () => ({ ctiProvider: mockCtiProvider }));

vi.mock('@ciperscope/logger', () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
}));

vi.mock('@ciperscope/config', () => ({ env: { REDIS_URL: 'redis://localhost:6379' } }));

vi.mock('../cti/CtiConfig', () => ({
  CtiConfig: { getGeoProvider: vi.fn(() => mockGeoProvider) },
}));

vi.mock('ioredis', () => ({ default: vi.fn(() => ({})) }));

import { processCTIJob } from '../cti-worker';

function baseJob(overrides: Partial<{ indicator: string; indicatorType: 'IP' | 'DOMAIN' | 'HASH' }> = {}) {
  return { indicator: '8.8.8.8', indicatorType: 'IP' as const, emailId: 'email-1', organizationId: 'org-1', ...overrides };
}

describe('processCTIJob — Phase H GeoIP enrichment wiring', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPrismaInstance.indicator.findUnique.mockResolvedValue({ id: 'ind-1', value: '8.8.8.8', type: 'IP' });
    mockPrismaInstance.threatIntelObservation.findFirst.mockResolvedValue(null);
    mockCtiProvider.enrichIp.mockResolvedValue({
      status: 'available',
      data: { provider: 'AbuseIPDB', verdict: 'CLEAN', confidence: 0, status: 'available', latencyMs: 5 },
    });
  });

  it('looks up and persists GeoLocation for a public IP indicator', async () => {
    mockGeoProvider.lookup.mockResolvedValue({
      providerName: 'MaxMind', country: 'United States', region: 'California', city: 'Mountain View',
      latitude: 37.4, longitude: -122.1, asn: 'AS15169', isp: 'Google LLC',
    });

    await processCTIJob(baseJob());

    expect(mockGeoProvider.lookup).toHaveBeenCalledWith('8.8.8.8');
    expect(mockPrismaInstance.geoLocation.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { ipAddress: '8.8.8.8' },
        create: expect.objectContaining({ ipAddress: '8.8.8.8', country: 'United States', asn: 'AS15169' }),
      })
    );
  });

  it('never calls the geo provider for a private IP indicator', async () => {
    mockPrismaInstance.indicator.findUnique.mockResolvedValue({ id: 'ind-2', value: '10.0.0.5', type: 'IP' });
    mockCtiProvider.enrichIp.mockResolvedValue({
      status: 'available',
      data: { provider: 'AbuseIPDB', verdict: 'CLEAN', confidence: 0, status: 'available', latencyMs: 5 },
    });

    await processCTIJob(baseJob({ indicator: '10.0.0.5' }));

    expect(mockGeoProvider.lookup).not.toHaveBeenCalled();
    expect(mockPrismaInstance.geoLocation.upsert).not.toHaveBeenCalled();
  });

  it('never calls the geo provider for a loopback IP indicator', async () => {
    mockPrismaInstance.indicator.findUnique.mockResolvedValue({ id: 'ind-3', value: '127.0.0.1', type: 'IP' });
    mockCtiProvider.enrichIp.mockResolvedValue({
      status: 'available',
      data: { provider: 'AbuseIPDB', verdict: 'CLEAN', confidence: 0, status: 'available', latencyMs: 5 },
    });

    await processCTIJob(baseJob({ indicator: '127.0.0.1' }));

    expect(mockGeoProvider.lookup).not.toHaveBeenCalled();
    expect(mockPrismaInstance.geoLocation.upsert).not.toHaveBeenCalled();
  });

  it('does not run GeoIP enrichment for non-IP indicators', async () => {
    mockCtiProvider.enrichDomain.mockResolvedValue({
      status: 'available',
      data: { provider: 'VirusTotal', verdict: 'CLEAN', confidence: 0, status: 'available', latencyMs: 5 },
    });

    await processCTIJob(baseJob({ indicator: 'example.com', indicatorType: 'DOMAIN' }));

    expect(mockGeoProvider.lookup).not.toHaveBeenCalled();
  });

  it('a GeoIP lookup failure does not fail the CTI job or block the primary reputation result', async () => {
    mockGeoProvider.lookup.mockRejectedValue(new Error('provider down'));

    const outcome = await processCTIJob(baseJob());

    expect(outcome.verdict).toBe('CLEAN');
    expect(mockPrismaInstance.geoLocation.upsert).not.toHaveBeenCalled();
  });

  it('a GeoLocation upsert failure does not fail the CTI job', async () => {
    mockGeoProvider.lookup.mockResolvedValue({ providerName: 'MaxMind', country: 'US' });
    mockPrismaInstance.geoLocation.upsert.mockRejectedValue(new Error('db down'));

    await expect(processCTIJob(baseJob())).resolves.toEqual(expect.objectContaining({ verdict: 'CLEAN' }));
  });

  it('when the geo provider returns null (no data), nothing is persisted', async () => {
    mockGeoProvider.lookup.mockResolvedValue(null);

    await processCTIJob(baseJob());

    expect(mockPrismaInstance.geoLocation.upsert).not.toHaveBeenCalled();
  });
});
