import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockPrismaInstance, mockCtiProvider, mockGeoProvider, mockDomainIntelProvider, mockDnsResolverInstance } = vi.hoisted(() => {
  return {
    mockPrismaInstance: {
      indicator: { findUnique: vi.fn(), create: vi.fn() },
      threatIntelObservation: { findFirst: vi.fn(), create: vi.fn(), update: vi.fn() },
      geoLocation: { upsert: vi.fn() },
      domainIntelligence: { upsert: vi.fn() },
      dnsObservation: { deleteMany: vi.fn(), createMany: vi.fn() },
      $transaction: vi.fn((ops: unknown[]) => Promise.all(ops)),
      $disconnect: vi.fn(),
    },
    mockCtiProvider: { enrichIp: vi.fn(), enrichDomain: vi.fn(), enrichHash: vi.fn() },
    mockGeoProvider: { lookup: vi.fn() },
    mockDomainIntelProvider: { lookup: vi.fn() },
    mockDnsResolverInstance: { resolvePtr: vi.fn(), getObservations: vi.fn() },
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

vi.mock('../domain-intel/DomainIntelConfig', () => ({
  DomainIntelConfig: { getDomainIntelProvider: vi.fn(() => mockDomainIntelProvider) },
}));

vi.mock('../verifier/DnsResolver', () => ({
  DnsResolver: vi.fn(() => mockDnsResolverInstance),
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
    mockDomainIntelProvider.lookup.mockResolvedValue({ status: 'NOT_CONFIGURED', data: null });
    mockDnsResolverInstance.resolvePtr.mockResolvedValue(['dns.google.']);
    mockDnsResolverInstance.getObservations.mockReturnValue([
      { queryName: '8.8.8.8', recordType: 'PTR', response: '["dns.google."]', rcode: 'NOERROR', durationMs: 12 },
    ]);
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

describe('processCTIJob — Phase N reverse-DNS (PTR) wiring', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPrismaInstance.indicator.findUnique.mockResolvedValue({ id: 'ind-1', value: '8.8.8.8', type: 'IP' });
    mockPrismaInstance.threatIntelObservation.findFirst.mockResolvedValue(null);
    mockCtiProvider.enrichIp.mockResolvedValue({
      status: 'available',
      data: { provider: 'AbuseIPDB', verdict: 'CLEAN', confidence: 0, status: 'available', latencyMs: 5 },
    });
    mockGeoProvider.lookup.mockResolvedValue(null);
    mockDnsResolverInstance.resolvePtr.mockResolvedValue(['dns.google.']);
    mockDnsResolverInstance.getObservations.mockReturnValue([
      { queryName: '8.8.8.8', recordType: 'PTR', response: '["dns.google."]', rcode: 'NOERROR', durationMs: 12 },
    ]);
  });

  it('resolves and persists a DnsObservation for a public IP indicator, scoped to the job\'s emailId', async () => {
    await processCTIJob(baseJob({ indicator: '8.8.8.8' }));

    expect(mockDnsResolverInstance.resolvePtr).toHaveBeenCalledWith('8.8.8.8');
    expect(mockPrismaInstance.dnsObservation.deleteMany).toHaveBeenCalledWith({
      where: { emailId: 'email-1', queryName: '8.8.8.8', recordType: 'PTR' },
    });
    expect(mockPrismaInstance.dnsObservation.createMany).toHaveBeenCalledWith({
      data: [{ emailId: 'email-1', queryName: '8.8.8.8', recordType: 'PTR', response: '["dns.google."]', rcode: 'NOERROR', durationMs: 12 }],
    });
  });

  it('never calls the DNS resolver for a private IP indicator', async () => {
    mockPrismaInstance.indicator.findUnique.mockResolvedValue({ id: 'ind-2', value: '10.0.0.5', type: 'IP' });

    await processCTIJob(baseJob({ indicator: '10.0.0.5' }));

    expect(mockDnsResolverInstance.resolvePtr).not.toHaveBeenCalled();
    expect(mockPrismaInstance.dnsObservation.createMany).not.toHaveBeenCalled();
  });

  it('does not run PTR resolution for non-IP indicators', async () => {
    mockCtiProvider.enrichDomain.mockResolvedValue({
      status: 'available',
      data: { provider: 'VirusTotal', verdict: 'CLEAN', confidence: 0, status: 'available', latencyMs: 5 },
    });
    mockDomainIntelProvider.lookup.mockResolvedValue({ status: 'NOT_CONFIGURED', data: null });

    await processCTIJob(baseJob({ indicator: 'example.com', indicatorType: 'DOMAIN' }));

    expect(mockDnsResolverInstance.resolvePtr).not.toHaveBeenCalled();
  });

  it('a PTR lookup failure does not fail the CTI job or block the primary reputation result', async () => {
    mockDnsResolverInstance.resolvePtr.mockRejectedValue(new Error('DNS_TIMEOUT'));

    const outcome = await processCTIJob(baseJob());

    expect(outcome.verdict).toBe('CLEAN');
    expect(mockPrismaInstance.dnsObservation.createMany).not.toHaveBeenCalled();
  });

  it('a DnsObservation persistence failure does not fail the CTI job', async () => {
    mockPrismaInstance.dnsObservation.createMany.mockRejectedValue(new Error('db down'));

    await expect(processCTIJob(baseJob())).resolves.toEqual(expect.objectContaining({ verdict: 'CLEAN' }));
  });

  it('when no PTR record exists (empty observations), nothing is persisted', async () => {
    mockDnsResolverInstance.resolvePtr.mockResolvedValue([]);
    mockDnsResolverInstance.getObservations.mockReturnValue([]);

    await processCTIJob(baseJob());

    expect(mockPrismaInstance.dnsObservation.createMany).not.toHaveBeenCalled();
  });
});

describe('processCTIJob — Phase L RDAP domain intelligence wiring', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPrismaInstance.indicator.findUnique.mockResolvedValue({ id: 'ind-1', value: 'evil-example.com', type: 'DOMAIN' });
    mockPrismaInstance.threatIntelObservation.findFirst.mockResolvedValue(null);
    mockCtiProvider.enrichDomain.mockResolvedValue({
      status: 'available',
      data: { provider: 'VirusTotal', verdict: 'MALICIOUS', confidence: 90, status: 'available', latencyMs: 5 },
    });
  });

  it('looks up and persists DomainIntelligence for a registrable domain, keyed by the registrable domain', async () => {
    mockDomainIntelProvider.lookup.mockResolvedValue({
      status: 'SUCCESS',
      data: {
        registrar: 'Evil Registrar LLC', registrationDate: new Date('2020-01-01'), expirationDate: new Date('2030-01-01'),
        nameservers: ['ns1.evil-example.com'], domainStatus: ['active'], rdapSource: 'https://rdap.example/',
      },
    });

    await processCTIJob(baseJob({ indicator: 'evil-example.com', indicatorType: 'DOMAIN' }));

    expect(mockDomainIntelProvider.lookup).toHaveBeenCalledWith('evil-example.com');
    expect(mockPrismaInstance.domainIntelligence.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { registrableDomain: 'evil-example.com' },
        create: expect.objectContaining({ registrableDomain: 'evil-example.com', status: 'SUCCESS', registrar: 'Evil Registrar LLC' }),
      })
    );
  });

  it('reduces a subdomain indicator to its registrable domain before lookup', async () => {
    mockPrismaInstance.indicator.findUnique.mockResolvedValue({ id: 'ind-2', value: 'mail.evil-example.com', type: 'DOMAIN' });
    mockDomainIntelProvider.lookup.mockResolvedValue({ status: 'NOT_FOUND', data: null });

    await processCTIJob(baseJob({ indicator: 'mail.evil-example.com', indicatorType: 'DOMAIN' }));

    expect(mockDomainIntelProvider.lookup).toHaveBeenCalledWith('evil-example.com');
  });

  it('never calls the RDAP provider for a private/reserved domain — persists PRIVATE_OR_RESERVED directly', async () => {
    mockPrismaInstance.indicator.findUnique.mockResolvedValue({ id: 'ind-3', value: 'internal.local', type: 'DOMAIN' });

    await processCTIJob(baseJob({ indicator: 'internal.local', indicatorType: 'DOMAIN' }));

    expect(mockDomainIntelProvider.lookup).not.toHaveBeenCalled();
    expect(mockPrismaInstance.domainIntelligence.upsert).toHaveBeenCalledWith(
      expect.objectContaining({ where: { registrableDomain: 'internal.local' }, create: expect.objectContaining({ status: 'PRIVATE_OR_RESERVED' }) })
    );
  });

  it('does not run RDAP enrichment for non-DOMAIN indicators', async () => {
    mockPrismaInstance.indicator.findUnique.mockResolvedValue({ id: 'ind-4', value: '8.8.8.8', type: 'IP' });
    mockCtiProvider.enrichIp.mockResolvedValue({ status: 'available', data: { provider: 'AbuseIPDB', verdict: 'CLEAN', confidence: 0, status: 'available', latencyMs: 5 } });

    await processCTIJob(baseJob({ indicator: '8.8.8.8', indicatorType: 'IP' }));

    expect(mockDomainIntelProvider.lookup).not.toHaveBeenCalled();
  });

  it('an RDAP lookup failure does not fail the CTI job or block the primary reputation result', async () => {
    mockDomainIntelProvider.lookup.mockRejectedValue(new Error('provider down'));

    const outcome = await processCTIJob(baseJob({ indicator: 'evil-example.com', indicatorType: 'DOMAIN' }));

    expect(outcome.verdict).toBe('MALICIOUS');
  });

  it('a DomainIntelligence upsert failure does not fail the CTI job', async () => {
    mockDomainIntelProvider.lookup.mockResolvedValue({ status: 'SUCCESS', data: { registrar: null, registrationDate: null, expirationDate: null, nameservers: [], domainStatus: [], rdapSource: 'https://rdap.example/' } });
    mockPrismaInstance.domainIntelligence.upsert.mockRejectedValue(new Error('db down'));

    await expect(processCTIJob(baseJob({ indicator: 'evil-example.com', indicatorType: 'DOMAIN' }))).resolves.toEqual(expect.objectContaining({ verdict: 'MALICIOUS' }));
  });
});
