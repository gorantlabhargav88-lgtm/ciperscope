import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ReliableCtiProvider } from '../ReliableCtiProvider';
import { ICtiProvider, CtiResult } from '../ICtiProvider';
import { NormalizedIoc } from '../../IocNormalizer';
import { ThreatVerdict, IndicatorType } from '@ciperscope/database';
import IORedis from 'ioredis';
import { createHash } from 'crypto';

class MockCtiProvider implements ICtiProvider {
  public readonly name = 'MockCti';
  public lookupResult: CtiResult = {
    status: ThreatVerdict.MALICIOUS,
    providerName: 'MockCti'
  };
  public shouldThrow = false;
  public delayMs = 0;
  public calls = 0;

  async lookup(): Promise<CtiResult> {
    this.calls++;
    if (this.delayMs > 0) {
      await new Promise(resolve => setTimeout(resolve, this.delayMs));
    }
    if (this.shouldThrow) {
      throw new Error('Provider error');
    }
    return this.lookupResult;
  }
}

describe('ReliableCtiProvider', () => {
  let mockRedis: Record<string, ReturnType<typeof vi.fn>>;
  let mockProvider: MockCtiProvider;
  let reliableProvider: ReliableCtiProvider;
  const testIoc: NormalizedIoc = { type: IndicatorType.IP, value: '1.2.3.4' };
  const expectedHash = createHash('sha256').update(testIoc.value).digest('hex');
  const expectedCacheKey = `cti:cache:v1:MockCti:IP:${expectedHash}`;

  beforeEach(() => {
    vi.useFakeTimers();
    mockRedis = {
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn().mockResolvedValue('OK')
    };
    mockProvider = new MockCtiProvider();
    reliableProvider = new ReliableCtiProvider(mockProvider, mockRedis as unknown as IORedis);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('A/G. cache miss -> provider called -> success -> result cached', async () => {
    const resultPromise = reliableProvider.lookup(testIoc);
    await vi.runAllTimersAsync();
    const result = await resultPromise;

    expect(mockProvider.calls).toBe(1);
    expect(result.status).toBe(ThreatVerdict.MALICIOUS);
    expect(mockRedis.get).toHaveBeenCalledWith(expectedCacheKey);
    expect(mockRedis.set).toHaveBeenCalledWith(expectedCacheKey, JSON.stringify(mockProvider.lookupResult), 'EX', 86400);
  });

  it('B. cache hit -> provider NOT called', async () => {
    mockRedis.get.mockResolvedValue(JSON.stringify({ status: ThreatVerdict.CLEAN, providerName: 'MockCti' }));

    const resultPromise = reliableProvider.lookup(testIoc);
    await vi.runAllTimersAsync();
    const result = await resultPromise;

    expect(mockProvider.calls).toBe(0);
    expect(result.status).toBe(ThreatVerdict.CLEAN);
  });

  it('C/D/E. deterministic SHA-256 cache key format', async () => {
    const resultPromise = reliableProvider.lookup({ type: IndicatorType.DOMAIN, value: 'example.com' });
    await vi.runAllTimersAsync();
    await resultPromise;

    const hash = createHash('sha256').update('example.com').digest('hex');
    expect(mockRedis.get).toHaveBeenCalledWith(`cti:cache:v1:MockCti:DOMAIN:${hash}`);
  });

  it('F. Redis failure -> provider still attempted', async () => {
    mockRedis.get.mockRejectedValue(new Error('Redis is down'));

    const resultPromise = reliableProvider.lookup(testIoc);
    await vi.runAllTimersAsync();
    const result = await resultPromise;

    expect(mockProvider.calls).toBe(1);
    expect(result.status).toBe(ThreatVerdict.MALICIOUS);
  });

  it('H. provider timeout -> UNKNOWN', async () => {
    mockProvider.delayMs = 3000;

    const promise = reliableProvider.lookup(testIoc);
    await vi.advanceTimersByTimeAsync(2001); // Advance past timeout
    const result = await promise;

    expect(result.status).toBe(ThreatVerdict.UNKNOWN);
    expect(result.metadata?.reliableFallbackReason).toBe('Provider Timeout');
  });

  it('I. provider exception -> UNKNOWN', async () => {
    mockProvider.shouldThrow = true;

    const promise = reliableProvider.lookup(testIoc);
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result.status).toBe(ThreatVerdict.UNKNOWN);
    expect(result.metadata?.reliableFallbackReason).toBe('Provider error');
  });

  it('L/M. circuit opens after failure threshold and prevents calls', async () => {
    mockProvider.shouldThrow = true;

    // Trigger 5 failures
    for (let i = 0; i < 5; i++) {
      const p = reliableProvider.lookup(testIoc);
      await vi.runAllTimersAsync();
      await p;
    }

    expect(mockProvider.calls).toBe(5);

    // 6th call should trip breaker instantly without calling provider
    const p6 = reliableProvider.lookup(testIoc);
    await vi.runAllTimersAsync();
    const result6 = await p6;

    expect(mockProvider.calls).toBe(5); // Still 5 calls!
    expect(result6.status).toBe(ThreatVerdict.UNKNOWN);
    expect(result6.metadata?.reliableFallbackReason).toBe('Circuit Breaker OPEN');
  });

  it('validates provider response and rejects malformed objects', async () => {
    mockProvider.lookupResult = null as unknown as CtiResult;
    const promiseNull = reliableProvider.lookup(testIoc);
    await vi.runAllTimersAsync();
    const resultNull = await promiseNull;
    expect(resultNull.status).toBe(ThreatVerdict.UNKNOWN);
    expect(resultNull.metadata?.reliableFallbackReason).toContain('result is not an object');
    expect(mockRedis.set).not.toHaveBeenCalled();

    mockProvider.lookupResult = { status: 'INVALID_STATUS' } as unknown as CtiResult;
    const promiseStatus = reliableProvider.lookup(testIoc);
    await vi.runAllTimersAsync();
    const resultStatus = await promiseStatus;
    expect(resultStatus.status).toBe(ThreatVerdict.UNKNOWN);
    expect(resultStatus.metadata?.reliableFallbackReason).toContain('invalid status');
    expect(mockRedis.set).not.toHaveBeenCalled();

    mockProvider.lookupResult = { status: ThreatVerdict.MALICIOUS } as unknown as CtiResult; // Missing providerName
    const promiseName = reliableProvider.lookup(testIoc);
    await vi.runAllTimersAsync();
    const resultName = await promiseName;
    expect(resultName.status).toBe(ThreatVerdict.UNKNOWN);
    expect(resultName.metadata?.reliableFallbackReason).toContain('missing, invalid, or oversized providerName');
    expect(mockRedis.set).not.toHaveBeenCalled();

    mockProvider.lookupResult = { status: ThreatVerdict.MALICIOUS, providerName: 'a'.repeat(256) } as unknown as CtiResult; // Oversized providerName
    const promiseOversizedName = reliableProvider.lookup(testIoc);
    await vi.runAllTimersAsync();
    const resultOversizedName = await promiseOversizedName;
    expect(resultOversizedName.status).toBe(ThreatVerdict.UNKNOWN);
    expect(resultOversizedName.metadata?.reliableFallbackReason).toContain('oversized providerName');
    expect(mockRedis.set).not.toHaveBeenCalled();

    mockProvider.lookupResult = { status: ThreatVerdict.MALICIOUS, providerName: 'Valid', metadata: { data: 'a'.repeat(5000) } } as unknown as CtiResult; // Oversized metadata
    const promiseOversizedMeta = reliableProvider.lookup(testIoc);
    await vi.runAllTimersAsync();
    const resultOversizedMeta = await promiseOversizedMeta;
    expect(resultOversizedMeta.status).toBe(ThreatVerdict.UNKNOWN);
    expect(resultOversizedMeta.metadata?.reliableFallbackReason).toContain('exceeds maximum permitted size');
    expect(mockRedis.set).not.toHaveBeenCalled();
  });

  it('validates confidence optional bounds properly', async () => {
    // confidence omitted -> valid
    mockProvider.lookupResult = { status: ThreatVerdict.CLEAN, providerName: 'Mock' } as CtiResult;
    let res = await reliableProvider.lookup(testIoc);
    expect(res.status).toBe(ThreatVerdict.CLEAN);

    // confidence 0 -> valid
    mockProvider.lookupResult = { status: ThreatVerdict.CLEAN, providerName: 'Mock', confidence: 0 } as CtiResult;
    res = await reliableProvider.lookup(testIoc);
    expect(res.status).toBe(ThreatVerdict.CLEAN);

    // confidence 50 -> valid
    mockProvider.lookupResult = { status: ThreatVerdict.CLEAN, providerName: 'Mock', confidence: 50 } as CtiResult;
    res = await reliableProvider.lookup(testIoc);
    expect(res.status).toBe(ThreatVerdict.CLEAN);

    // confidence 100 -> valid
    mockProvider.lookupResult = { status: ThreatVerdict.CLEAN, providerName: 'Mock', confidence: 100 } as CtiResult;
    res = await reliableProvider.lookup(testIoc);
    expect(res.status).toBe(ThreatVerdict.CLEAN);

    // confidence -1 -> invalid
    mockProvider.lookupResult = { status: ThreatVerdict.CLEAN, providerName: 'Mock', confidence: -1 } as CtiResult;
    res = await reliableProvider.lookup(testIoc);
    expect(res.status).toBe(ThreatVerdict.UNKNOWN);
    expect(res.metadata?.reliableFallbackReason).toContain('invalid confidence');

    // confidence 101 -> invalid
    mockProvider.lookupResult = { status: ThreatVerdict.CLEAN, providerName: 'Mock', confidence: 101 } as CtiResult;
    res = await reliableProvider.lookup(testIoc);
    expect(res.status).toBe(ThreatVerdict.UNKNOWN);
    expect(res.metadata?.reliableFallbackReason).toContain('invalid confidence');

    // confidence "high" -> invalid
    mockProvider.lookupResult = { status: ThreatVerdict.CLEAN, providerName: 'Mock', confidence: 'high' } as unknown as CtiResult;
    res = await reliableProvider.lookup(testIoc);
    expect(res.status).toBe(ThreatVerdict.UNKNOWN);

    // confidence null -> invalid
    mockProvider.lookupResult = { status: ThreatVerdict.CLEAN, providerName: 'Mock', confidence: null } as unknown as CtiResult;
    res = await reliableProvider.lookup(testIoc);
    expect(res.status).toBe(ThreatVerdict.UNKNOWN);
  });

  it('validates cache read data and falls back to provider if cache is poisoned', async () => {
    // Valid cache
    mockRedis.get.mockResolvedValueOnce(JSON.stringify({ status: ThreatVerdict.MALICIOUS, providerName: 'MockCache' }));
    let res = await reliableProvider.lookup(testIoc);
    expect(res.status).toBe(ThreatVerdict.MALICIOUS);
    expect(res.providerName).toBe('MockCache');
    expect(mockProvider.calls).toBe(0);

    // Malformed cache (should fall through to provider which returns default MALICIOUS)
    mockRedis.get.mockResolvedValueOnce(JSON.stringify({ status: 'INVALID_STATUS' }));
    res = await reliableProvider.lookup(testIoc);
    // Since cache is invalid, it catches error, falls to provider
    expect(res.status).toBe(ThreatVerdict.MALICIOUS);
    expect(mockProvider.calls).toBe(1);
  });
});

import { ReliableGeoProvider } from '../ReliableGeoProvider';
import { IGeoProvider, GeoLocationResult } from '../ICtiProvider';

class MockGeoProvider implements IGeoProvider {
  public readonly name = 'MockGeo';
  public lookupResult: GeoLocationResult | null = {
    country: 'US',
    providerName: 'MockGeo'
  };

  async lookup(): Promise<GeoLocationResult | null> {
    return this.lookupResult;
  }
}

describe('ReliableGeoProvider', () => {
  let mockRedis: Record<string, ReturnType<typeof vi.fn>>;
  let mockGeoProvider: MockGeoProvider;
  let reliableGeoProvider: ReliableGeoProvider;

  beforeEach(() => {
    vi.useFakeTimers();
    mockRedis = {
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn().mockResolvedValue('OK')
    };
    mockGeoProvider = new MockGeoProvider();
    reliableGeoProvider = new ReliableGeoProvider(mockGeoProvider, mockRedis as unknown as IORedis);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('validates geo provider response and rejects malformed objects', async () => {
    // Missing providerName
    mockGeoProvider.lookupResult = { country: 'US' } as unknown as GeoLocationResult;
    const promiseStatus = reliableGeoProvider.lookup('1.2.3.4');
    await vi.runAllTimersAsync();
    const resultStatus = await promiseStatus;
    expect(resultStatus).toBeNull();
    expect(mockRedis.set).not.toHaveBeenCalled();

    // Oversized providerName
    mockGeoProvider.lookupResult = { providerName: 'a'.repeat(256), country: 'US' } as unknown as GeoLocationResult;
    const promiseOversizedName = reliableGeoProvider.lookup('1.2.3.4');
    await vi.runAllTimersAsync();
    const resultOversizedName = await promiseOversizedName;
    expect(resultOversizedName).toBeNull();
    expect(mockRedis.set).not.toHaveBeenCalled();

    // Oversized country
    mockGeoProvider.lookupResult = { providerName: 'Mock', country: 'a'.repeat(256) } as unknown as GeoLocationResult;
    const promiseOversizedCountry = reliableGeoProvider.lookup('1.2.3.4');
    await vi.runAllTimersAsync();
    const resultOversizedCountry = await promiseOversizedCountry;
    expect(resultOversizedCountry).toBeNull();
    expect(mockRedis.set).not.toHaveBeenCalled();

    mockGeoProvider.lookupResult = 'stringResult' as unknown as GeoLocationResult;
    const promiseString = reliableGeoProvider.lookup('1.2.3.4');
    await vi.runAllTimersAsync();
    const resultString = await promiseString;
    expect(resultString).toBeNull();
    expect(mockRedis.set).not.toHaveBeenCalled();

    // Valid result with all fields
    mockGeoProvider.lookupResult = { country: 'CA', providerName: 'MockGeo', city: 'Toronto', asn: 'AS123', isp: 'Bell' };
    const promiseValid = reliableGeoProvider.lookup('1.2.3.4');
    await vi.runAllTimersAsync();
    const resultValid = await promiseValid;
    expect(resultValid?.country).toBe('CA');
    expect(mockRedis.set).toHaveBeenCalled();
  });

  it('validates geo optional fields properly', async () => {
    // GEO result without country -> valid
    mockGeoProvider.lookupResult = { providerName: 'MockGeo' };
    let res = await reliableGeoProvider.lookup('1.2.3.4');
    await vi.runAllTimersAsync();
    expect(res?.providerName).toBe('MockGeo');

    // GEO result with invalid country type -> rejected
    mockGeoProvider.lookupResult = { providerName: 'MockGeo', country: 123 } as unknown as GeoLocationResult;
    res = await reliableGeoProvider.lookup('1.2.3.4');
    await vi.runAllTimersAsync();
    expect(res).toBeNull();

    // GEO result with invalid asn type -> rejected
    mockGeoProvider.lookupResult = { providerName: 'MockGeo', asn: 123 } as unknown as GeoLocationResult;
    res = await reliableGeoProvider.lookup('1.2.3.4');
    await vi.runAllTimersAsync();
    expect(res).toBeNull();
  });

  it('validates geo cache read data and falls back to provider if cache is poisoned', async () => {
    // Valid cache
    mockRedis.get.mockResolvedValueOnce(JSON.stringify({ country: 'US', providerName: 'MockCache' }));
    let res = await reliableGeoProvider.lookup('1.2.3.4');
    await vi.runAllTimersAsync();
    expect(res?.country).toBe('US');
    expect(res?.providerName).toBe('MockCache');

    // Malformed cache
    mockRedis.get.mockResolvedValueOnce(JSON.stringify({ country: 123 }));
    mockGeoProvider.lookupResult = { providerName: 'Fallback', country: 'CA' };
    res = await reliableGeoProvider.lookup('1.2.3.4');
    await vi.runAllTimersAsync();
    expect(res?.country).toBe('CA');
    expect(res?.providerName).toBe('Fallback');
  });
});
