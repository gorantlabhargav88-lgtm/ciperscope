import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockReverse } = vi.hoisted(() => ({ mockReverse: vi.fn() }));
vi.mock('dns/promises', () => ({ default: { reverse: mockReverse } }));

import { DnsResolver } from '../DnsResolver';

describe('DnsResolver.resolvePtr (Phase H reverse-DNS)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns PTR hostnames for a real reverse lookup', async () => {
    mockReverse.mockResolvedValue(['dns.google']);
    const resolver = new DnsResolver();
    const result = await resolver.resolvePtr('8.8.8.8');
    expect(result).toEqual(['dns.google']);
  });

  it('returns an empty array (not an error) when no PTR record exists', async () => {
    mockReverse.mockRejectedValue(Object.assign(new Error('not found'), { code: 'ENOTFOUND' }));
    const resolver = new DnsResolver();
    const result = await resolver.resolvePtr('203.0.113.5');
    expect(result).toEqual([]);
  });

  it('caches repeated lookups for the same IP (only one real DNS call)', async () => {
    mockReverse.mockResolvedValue(['dns.google']);
    const resolver = new DnsResolver();
    await resolver.resolvePtr('8.8.8.8');
    await resolver.resolvePtr('8.8.8.8');
    expect(mockReverse).toHaveBeenCalledTimes(1);
  });

  it('records a DNS observation with query name, record type PTR, and duration', async () => {
    mockReverse.mockResolvedValue(['dns.google']);
    const resolver = new DnsResolver();
    await resolver.resolvePtr('8.8.8.8');
    const observations = resolver.getObservations();
    expect(observations).toContainEqual(
      expect.objectContaining({ queryName: '8.8.8.8', recordType: 'PTR', rcode: 'NOERROR' })
    );
  });

  it('enforces the shared max-lookups bound across resolvePtr calls', async () => {
    mockReverse.mockResolvedValue(['host']);
    const resolver = new DnsResolver(2, 2000);
    await resolver.resolvePtr('1.1.1.1');
    await resolver.resolvePtr('2.2.2.2');
    await expect(resolver.resolvePtr('3.3.3.3')).rejects.toThrow(/DNS Lookup limit exceeded/);
  });
});
