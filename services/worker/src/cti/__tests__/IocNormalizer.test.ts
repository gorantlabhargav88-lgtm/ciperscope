import { describe, it, expect } from 'vitest';
import { IocNormalizer } from '../IocNormalizer';
import { IndicatorType } from '@ciperscope/database';

describe('IocNormalizer', () => {
  it('normalizes valid IPv4 addresses', () => {
    const result = IocNormalizer.normalizeIp(' 192.168.1.1 ');
    expect(result).toEqual({ type: IndicatorType.IP, value: '192.168.1.1' });
  });

  it('rejects invalid IPs', () => {
    expect(IocNormalizer.normalizeIp('999.999.999.999')).toBeNull(); // wait, our regex might accept this if it just checks digits, but let's test a clearly bad one
    expect(IocNormalizer.normalizeIp('not-an-ip')).toBeNull();
  });

  it('normalizes valid domains', () => {
    const result = IocNormalizer.normalizeDomain(' EXamPLE.COM ');
    expect(result).toEqual({ type: IndicatorType.DOMAIN, value: 'example.com' });
  });

  it('rejects invalid domains', () => {
    expect(IocNormalizer.normalizeDomain('http://example.com')).toBeNull(); // Should be rejected by regex
    expect(IocNormalizer.normalizeDomain('example')).toBeNull(); // Needs TLD
  });

  it('extracts base domain from URLs', () => {
    // Should drop path, query params, etc.
    const result = IocNormalizer.normalizeUrl('https://example.com/malicious/path?user=123');
    expect(result).toEqual({ type: IndicatorType.DOMAIN, value: 'example.com' });
  });

  it('rejects malformed URLs', () => {
    expect(IocNormalizer.normalizeUrl('not-a-url')).toBeNull();
  });

  it('normalizes valid SHA256 hashes', () => {
    const hash = 'a'.repeat(64);
    const result = IocNormalizer.normalizeHash(` ${hash.toUpperCase()} `);
    expect(result).toEqual({ type: IndicatorType.HASH, value: hash });
  });

  it('rejects invalid hashes', () => {
    expect(IocNormalizer.normalizeHash('short-hash')).toBeNull();
    expect(IocNormalizer.normalizeHash('a'.repeat(65))).toBeNull();
  });
});
