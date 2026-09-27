import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SpfVerifier } from '../SpfVerifier';
import { DnsResolver } from '../DnsResolver';

describe('SpfVerifier — Focused Authentication Tests', () => {
  let resolver: DnsResolver;
  let verifier: SpfVerifier;

  beforeEach(() => {
    resolver = new DnsResolver(50, 5000);
    verifier = new SpfVerifier(resolver);
  });

  it('evaluates PASS when sender IP matches ip4 mechanism in SPF record', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockResolvedValue(['v=spf1 ip4:198.51.100.1 -all']);
    const result = await verifier.verify('example.com', '198.51.100.1');

    expect(result.result).toBe('PASS');
    expect(result.domain).toBe('example.com');
    expect(result.evaluatedIp).toBe('198.51.100.1');
    expect(result.matchedMechanism).toBe('ip4:198.51.100.1');
  });

  it('evaluates FAIL when sender IP does not match and policy is -all', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockResolvedValue(['v=spf1 ip4:198.51.100.1 -all']);
    const result = await verifier.verify('example.com', '203.0.113.5');

    expect(result.result).toBe('FAIL');
    expect(result.domain).toBe('example.com');
    expect(result.evaluatedIp).toBe('203.0.113.5');
    expect(result.matchedMechanism).toBe('-all');
  });

  it('evaluates SOFTFAIL when sender IP does not match and policy is ~all', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockResolvedValue(['v=spf1 ip4:198.51.100.1 ~all']);
    const result = await verifier.verify('example.com', '203.0.113.5');

    expect(result.result).toBe('SOFTFAIL');
    expect(result.domain).toBe('example.com');
    expect(result.matchedMechanism).toBe('~all');
  });

  it('evaluates NEUTRAL when policy qualifier is ?all', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockResolvedValue(['v=spf1 ?all']);
    const result = await verifier.verify('example.com', '203.0.113.5');

    expect(result.result).toBe('NEUTRAL');
    expect(result.matchedMechanism).toBe('?all');
  });

  it('returns NONE when no SPF record is published for domain', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockResolvedValue(['other-txt-record']);
    const result = await verifier.verify('example.com', '198.51.100.1');

    expect(result.result).toBe('NONE');
    expect(result.explanation).toContain('No SPF record found');
  });

  it('returns PERMERROR when multiple SPF records are published', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockResolvedValue([
      'v=spf1 ip4:198.51.100.1 -all',
      'v=spf1 ip4:198.51.100.2 -all'
    ]);
    const result = await verifier.verify('example.com', '198.51.100.1');

    expect(result.result).toBe('PERMERROR');
    expect(result.explanation).toContain('Multiple SPF records found');
  });

  it('supports CIDR blocks in ip4 mechanism', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockResolvedValue(['v=spf1 ip4:198.51.100.0/24 -all']);
    const match = await verifier.verify('example.com', '198.51.100.42');
    expect(match.result).toBe('PASS');

    const noMatch = await verifier.verify('example.com', '198.51.101.42');
    expect(noMatch.result).toBe('FAIL');
  });

  it('handles recursive include: mechanisms safely', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockImplementation(async (domain: string) => {
      if (domain === 'example.com') return ['v=spf1 include:_spf.example.com -all'];
      if (domain === '_spf.example.com') return ['v=spf1 ip4:192.0.2.1 -all'];
      return [];
    });

    const result = await verifier.verify('example.com', '192.0.2.1');
    expect(result.result).toBe('PASS');
    expect(result.domain).toBe('example.com');
  });
});
