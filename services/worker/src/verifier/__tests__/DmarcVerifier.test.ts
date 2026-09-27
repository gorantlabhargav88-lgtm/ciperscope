import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DmarcVerifier } from '../DmarcVerifier';
import { DnsResolver } from '../DnsResolver';

describe('DmarcVerifier — Focused Authentication Tests', () => {
  let resolver: DnsResolver;
  let verifier: DmarcVerifier;

  beforeEach(() => {
    resolver = new DnsResolver(50, 5000);
    verifier = new DmarcVerifier(resolver);
  });

  it('evaluates PASS when SPF passes with relaxed domain alignment', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockResolvedValue(['v=DMARC1; p=reject; aspf=r; adkim=r']);
    const result = await verifier.verify(
      'mail.example.com',
      'example.com',
      'PASS',
      null,
      'NONE'
    );

    expect(result.result).toBe('PASS');
    expect(result.orgDomain).toBe('example.com');
    expect(result.policy).toBe('reject');
    expect(result.spfAlignment).toBe('relaxed');
    expect(result.explanation).toContain('DMARC pass');
  });

  it('evaluates PASS when DKIM passes with aligned domain', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockResolvedValue(['v=DMARC1; p=quarantine; adkim=r']);
    const result = await verifier.verify(
      'example.com',
      null,
      'NONE',
      'example.com',
      'PASS'
    );

    expect(result.result).toBe('PASS');
    expect(result.policy).toBe('quarantine');
    expect(result.dkimAlignment).toBe('relaxed');
  });

  it('evaluates FAIL when both SPF and DKIM fail or are unaligned', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockResolvedValue(['v=DMARC1; p=reject']);
    const result = await verifier.verify(
      'example.com',
      'attacker.com',
      'PASS', // passes for attacker.com, but unaligned with example.com!
      'attacker.com',
      'PASS'  // passes for attacker.com, but unaligned!
    );

    expect(result.result).toBe('FAIL');
    expect(result.spfAlignment).toBe('unaligned');
    expect(result.dkimAlignment).toBe('unaligned');
    expect(result.explanation).toContain('DMARC fail');
  });

  it('returns NONE when no DMARC record exists for domain or org domain', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockResolvedValue([]);
    const result = await verifier.verify(
      'example.com',
      'example.com',
      'PASS',
      'example.com',
      'PASS'
    );

    expect(result.result).toBe('NONE');
    expect(result.policy).toBeNull();
    expect(result.explanation).toContain('No DMARC record found');
  });

  it('returns PERMERROR when multiple DMARC records are found', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockResolvedValue([
      'v=DMARC1; p=reject',
      'v=DMARC1; p=none'
    ]);
    const result = await verifier.verify(
      'example.com',
      'example.com',
      'PASS',
      null,
      'NONE'
    );

    expect(result.result).toBe('PERMERROR');
    expect(result.explanation).toContain('Multiple DMARC records found');
  });

  it('enforces strict alignment mode (aspf=s / adkim=s)', async () => {
    vi.spyOn(resolver, 'resolveTxt').mockResolvedValue(['v=DMARC1; p=reject; aspf=s; adkim=s']);

    // Subdomain headerFrom with root domain spf should fail in strict mode
    const subResult = await verifier.verify(
      'sub.example.com',
      'example.com',
      'PASS',
      null,
      'NONE'
    );
    expect(subResult.result).toBe('FAIL');
    expect(subResult.spfAlignment).toBe('unaligned');

    // Exact match passes in strict mode
    const exactResult = await verifier.verify(
      'example.com',
      'example.com',
      'PASS',
      null,
      'NONE'
    );
    expect(exactResult.result).toBe('PASS');
    expect(exactResult.spfAlignment).toBe('strict');
  });

  it('returns PERMERROR for invalid header From domain', async () => {
    const result = await verifier.verify(
      'invalid..domain..',
      null,
      'NONE',
      null,
      'NONE'
    );

    expect(result.result).toBe('PERMERROR');
    expect(result.explanation).toContain('Invalid Header From domain');
  });
});
