import { describe, it, expect } from 'vitest';
import { detectBrandImpersonation } from '../BrandImpersonationDetector';

describe('detectBrandImpersonation', () => {
  it('does not flag the real, exact brand domain', () => {
    const result = detectBrandImpersonation('amazon.com');
    expect(result.indicators).toEqual([]);
  });

  it('does not flag a legitimate subdomain of the real brand domain', () => {
    const result = detectBrandImpersonation('www.amazon.com');
    expect(result.indicators).toEqual([]);
  });

  it('flags amaz0n.com as a typosquat (digit-for-letter substitution)', () => {
    const result = detectBrandImpersonation('amaz0n.com');
    expect(result.indicators).toContain('BRAND_IMPERSONATION_HOMOGLYPH');
    expect(result.descriptions[0]).toMatch(/amaz0n\.com/);
  });

  it('flags a Cyrillic-homoglyph "amazоn.com" (Cyrillic о) as impersonation', () => {
    // eslint-disable-next-line no-irregular-whitespace
    const cyrillicHost = 'amaz' + 'о' + 'n.com'; // U+043E CYRILLIC SMALL LETTER O
    const result = detectBrandImpersonation(cyrillicHost);
    expect(result.indicators).toContain('BRAND_IMPERSONATION_HOMOGLYPH');
  });

  it('flags amazon-login.example.com as a deceptive subdomain, not the real domain', () => {
    const result = detectBrandImpersonation('amazon-login.example.com');
    expect(result.indicators).toContain('BRAND_IMPERSONATION_SUBDOMAIN');
    expect(result.descriptions[0]).toMatch(/example\.com/);
  });

  it('flags amazon.com.example.com (brand-as-subdomain trick) as a deceptive subdomain', () => {
    const result = detectBrandImpersonation('amazon.com.example.com');
    expect(result.indicators).toContain('BRAND_IMPERSONATION_SUBDOMAIN');
  });

  it('does not false-positive on an unrelated shortener domain', () => {
    const result = detectBrandImpersonation('bit.ly');
    expect(result.indicators).toEqual([]);
  });

  it('does not false-positive on an unrelated everyday domain', () => {
    const result = detectBrandImpersonation('github.com');
    expect(result.indicators).toEqual([]);
  });

  it('flags a typosquat with a small edit distance (paypa1.com)', () => {
    const result = detectBrandImpersonation('paypa1.com');
    expect(result.indicators.some((i) => i.startsWith('BRAND_IMPERSONATION'))).toBe(true);
  });

  it('returns empty indicators for an empty hostname', () => {
    expect(detectBrandImpersonation('')).toEqual({ indicators: [], descriptions: [] });
  });
});
