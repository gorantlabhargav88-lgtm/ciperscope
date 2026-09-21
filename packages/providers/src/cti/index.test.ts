import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import dns from 'dns';
import { HttpClient } from '@ciperscope/http-client';
import { ProductionCTILayer } from './index';

/**
 * Proves the CTI layer genuinely routes through the existing SSRF-hardened
 * HttpClient (packages/http-client) rather than raw fetch — both for the
 * happy path (mocking HttpClient's underlying axios transport, exactly the
 * pattern already used in packages/http-client/src/index.test.ts) and for
 * SSRF blocking (using a REAL HttpClient instance with a mocked DNS
 * resolution, so the actual guard code executes through the real CTI call
 * path, not a stand-in).
 */

function mockClientResponse(client: HttpClient, response: unknown) {
  (client as any).axiosInstance.request = vi.fn().mockResolvedValue({ data: response });
  return (client as any).axiosInstance.request as ReturnType<typeof vi.fn>;
}

function mockClientRejection(client: HttpClient, error: unknown) {
  (client as any).axiosInstance.request = vi.fn().mockRejectedValue(error);
  return (client as any).axiosInstance.request as ReturnType<typeof vi.fn>;
}

describe('ProductionCTILayer — routes through the SSRF-hardened HttpClient', () => {
  const originalAbuseKey = process.env.ABUSEIPDB_API_KEY;
  const originalVtKey = process.env.VIRUSTOTAL_API_KEY;
  const originalRedisUrl = process.env.REDIS_URL;

  beforeEach(() => {
    process.env.ABUSEIPDB_API_KEY = 'test-abuseipdb-key-do-not-leak';
    process.env.VIRUSTOTAL_API_KEY = 'test-virustotal-key-do-not-leak';
    delete process.env.REDIS_URL; // most tests don't need a real cache backend
  });

  afterEach(() => {
    process.env.ABUSEIPDB_API_KEY = originalAbuseKey;
    process.env.VIRUSTOTAL_API_KEY = originalVtKey;
    process.env.REDIS_URL = originalRedisUrl;
    vi.restoreAllMocks();
  });

  describe('A. AbuseIPDB requests', () => {
    it('a successful request maps to the correct verdict/confidence and calls the AbuseIPDB HttpClient with the right URL/headers', async () => {
      const abuseIpdbClient = new HttpClient('AbuseIPDB-test');
      const requestSpy = mockClientResponse(abuseIpdbClient, { data: { abuseConfidenceScore: 80 } });
      const provider = new ProductionCTILayer({ abuseIpdbClient, virusTotalClient: new HttpClient('VT-unused') });

      const result = await provider.enrichIp('1.2.3.4');

      expect(result.status).toBe('available');
      expect(result.data.verdict).toBe('MALICIOUS');
      expect(result.data.confidence).toBe(80);
      expect(requestSpy).toHaveBeenCalledTimes(1);
      const calledConfig = requestSpy.mock.calls[0][0];
      expect(calledConfig.url).toContain('api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4');
      expect(calledConfig.headers).toMatchObject({ Key: 'test-abuseipdb-key-do-not-leak', Accept: 'application/json' });
    });

    it('returns not_configured (no HTTP call at all) when no API key is set', async () => {
      delete process.env.ABUSEIPDB_API_KEY;
      const abuseIpdbClient = new HttpClient('AbuseIPDB-test');
      const requestSpy = mockClientResponse(abuseIpdbClient, {});
      const provider = new ProductionCTILayer({ abuseIpdbClient, virusTotalClient: new HttpClient('VT-unused') });

      const result = await provider.enrichIp('1.2.3.4');

      expect(result.status).toBe('not_configured');
      expect(requestSpy).not.toHaveBeenCalled();
    });
  });

  describe('B. VirusTotal requests', () => {
    it('a successful domain request maps to the correct verdict/confidence and calls the VirusTotal HttpClient with the right URL/headers', async () => {
      const virusTotalClient = new HttpClient('VirusTotal-test');
      const requestSpy = mockClientResponse(virusTotalClient, {
        data: { attributes: { last_analysis_stats: { malicious: 3, suspicious: 1, harmless: 6, undetected: 0 } } }
      });
      const provider = new ProductionCTILayer({ abuseIpdbClient: new HttpClient('AB-unused'), virusTotalClient });

      const result = await provider.enrichDomain('evil.example.com');

      expect(result.status).toBe('available');
      expect(result.data.verdict).toBe('MALICIOUS');
      expect(result.data.confidence).toBe(40); // (3+1)/10 * 100
      const calledConfig = requestSpy.mock.calls[0][0];
      expect(calledConfig.url).toContain('virustotal.com/api/v3/domains/evil.example.com');
      expect(calledConfig.headers).toMatchObject({ 'x-apikey': 'test-virustotal-key-do-not-leak' });
    });

    it('a hash lookup uses the /files endpoint', async () => {
      const virusTotalClient = new HttpClient('VirusTotal-test');
      const requestSpy = mockClientResponse(virusTotalClient, { data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 10, undetected: 0 } } } });
      const provider = new ProductionCTILayer({ abuseIpdbClient: new HttpClient('AB-unused'), virusTotalClient });

      await provider.enrichHash('deadbeef');

      expect(requestSpy.mock.calls[0][0].url).toContain('virustotal.com/api/v3/files/deadbeef');
    });
  });

  describe('C. SSRF protection is genuinely exercised through the CTI call path', () => {
    it('a real HttpClient instance blocks a DNS-rebound private-IP destination when called via enrichIp', async () => {
      const lookupSpy = vi.spyOn(dns, 'lookup').mockImplementation((_hostname: any, _options: any, callback: any) => {
        callback(null, [{ address: '127.0.0.1', family: 4 }]);
      });

      // A REAL HttpClient (not mocked) so its actual SSRF guard code runs.
      const abuseIpdbClient = new HttpClient('AbuseIPDB-real-ssrf-test');
      const provider = new ProductionCTILayer({ abuseIpdbClient, virusTotalClient: new HttpClient('VT-unused') });

      const result = await provider.enrichIp('8.8.8.8');

      // The request must be blocked before any data is returned — never
      // treated as a successful lookup, and never silently returns
      // whatever a private/internal host might have served.
      expect(result.status).not.toBe('available');
      expect(result.data.status).toBe('unavailable');
      lookupSpy.mockRestore();
    });

    it('blocks the cloud metadata address (169.254.169.254) the same way', async () => {
      const lookupSpy = vi.spyOn(dns, 'lookup').mockImplementation((_hostname: any, _options: any, callback: any) => {
        callback(null, [{ address: '169.254.169.254', family: 4 }]);
      });

      const virusTotalClient = new HttpClient('VirusTotal-real-ssrf-test');
      const provider = new ProductionCTILayer({ abuseIpdbClient: new HttpClient('AB-unused'), virusTotalClient });

      const result = await provider.enrichDomain('evil.example.com');

      expect(result.status).not.toBe('available');
      expect(result.data.status).toBe('unavailable');
      lookupSpy.mockRestore();
    });

    it('the injected HttpClient carries the same redirect-validation config as production instances (already unit-tested in packages/http-client)', () => {
      const abuseIpdbClient = new HttpClient('AbuseIPDB-redirect-check');
      const provider = new ProductionCTILayer({ abuseIpdbClient, virusTotalClient: new HttpClient('VT-unused') });
      expect(provider).toBeDefined();
      const beforeRedirect = (abuseIpdbClient as any).axiosInstance.defaults.beforeRedirect;
      expect(beforeRedirect).toBeDefined();
      expect(() => beforeRedirect({ protocol: 'http:', hostname: '127.0.0.1', path: '/' })).toThrow(/SSRF attempt blocked/);
    });
  });

  describe('E. Timeout and error propagation, without leaking credentials', () => {
    it('maps an axios timeout (ECONNABORTED) to status timeout, retryable', async () => {
      const abuseIpdbClient = new HttpClient('AbuseIPDB-test');
      mockClientRejection(abuseIpdbClient, { code: 'ECONNABORTED', message: 'timeout of 5000ms exceeded' });
      const provider = new ProductionCTILayer({ abuseIpdbClient, virusTotalClient: new HttpClient('VT-unused') });

      const result = await provider.enrichIp('1.2.3.4');

      expect(result.data.status).toBe('timeout');
      expect(result.data.retryable).toBe(true);
    });

    it('maps a 401 response to unauthorized, not retryable, and never echoes the API key', async () => {
      const abuseIpdbClient = new HttpClient('AbuseIPDB-test');
      mockClientRejection(abuseIpdbClient, { response: { status: 401, data: { error: 'invalid key' } } });
      const provider = new ProductionCTILayer({ abuseIpdbClient, virusTotalClient: new HttpClient('VT-unused') });

      const result = await provider.enrichIp('1.2.3.4');

      expect(result.data.status).toBe('unauthorized');
      expect(result.data.retryable).toBe(false);
      expect(JSON.stringify(result)).not.toContain('test-abuseipdb-key-do-not-leak');
    });

    it('maps a 429 response to rate_limited, retryable', async () => {
      const virusTotalClient = new HttpClient('VirusTotal-test');
      mockClientRejection(virusTotalClient, { response: { status: 429 } });
      const provider = new ProductionCTILayer({ abuseIpdbClient: new HttpClient('AB-unused'), virusTotalClient });

      const result = await provider.enrichDomain('example.com');

      expect(result.data.status).toBe('rate_limited');
      expect(result.data.retryable).toBe(true);
    });

    it('maps a 500 response to provider_error, retryable', async () => {
      const abuseIpdbClient = new HttpClient('AbuseIPDB-test');
      mockClientRejection(abuseIpdbClient, { response: { status: 500 } });
      const provider = new ProductionCTILayer({ abuseIpdbClient, virusTotalClient: new HttpClient('VT-unused') });

      const result = await provider.enrichIp('1.2.3.4');

      expect(result.data.status).toBe('provider_error');
      expect(result.data.retryable).toBe(true);
    });

    it('maps a 400 response to provider_error, NOT retryable', async () => {
      const abuseIpdbClient = new HttpClient('AbuseIPDB-test');
      mockClientRejection(abuseIpdbClient, { response: { status: 400 } });
      const provider = new ProductionCTILayer({ abuseIpdbClient, virusTotalClient: new HttpClient('VT-unused') });

      const result = await provider.enrichIp('1.2.3.4');

      expect(result.data.status).toBe('provider_error');
      expect(result.data.retryable).toBe(false);
    });

    it('a generic/unrecognized rejection (e.g. an open circuit breaker) is classified as unavailable, retryable, and never throws out of enrichIp', async () => {
      const abuseIpdbClient = new HttpClient('AbuseIPDB-test');
      mockClientRejection(abuseIpdbClient, new Error('Breaker is open'));
      const provider = new ProductionCTILayer({ abuseIpdbClient, virusTotalClient: new HttpClient('VT-unused') });

      const result = await provider.enrichIp('1.2.3.4');

      expect(result.data.status).toBe('unavailable');
      expect(result.data.retryable).toBe(true);
    });
  });

  describe('F. Provider authentication is passed through correctly and never leaked', () => {
    it('the AbuseIPDB key is sent as the Key header, and never appears in a thrown/returned error', async () => {
      const abuseIpdbClient = new HttpClient('AbuseIPDB-test');
      const requestSpy = mockClientRejection(abuseIpdbClient, { response: { status: 403, data: { key: process.env.ABUSEIPDB_API_KEY } } });
      const provider = new ProductionCTILayer({ abuseIpdbClient, virusTotalClient: new HttpClient('VT-unused') });

      const result = await provider.enrichIp('1.2.3.4');

      expect(requestSpy.mock.calls[0][0].headers.Key).toBe('test-abuseipdb-key-do-not-leak');
      expect(result.data.status).toBe('unauthorized');
      // The normalized result CiperScope actually persists/returns must never carry the raw key.
      expect(JSON.stringify(result)).not.toContain('test-abuseipdb-key-do-not-leak');
    });
  });
});
