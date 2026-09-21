import { Redis } from 'ioredis';
import { HttpClient } from '@ciperscope/http-client';

export type CTIStatus = 'available' | 'unavailable' | 'degraded' | 'not_found' | 'rate_limited' | 'unauthorized' | 'timeout' | 'provider_error' | 'not_configured';
export type IndicatorType = 'IP' | 'DOMAIN' | 'URL' | 'HASH' | 'EMAIL_ADDRESS' | 'ASN';
export type ThreatVerdict = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';

export interface CTINormalizedResult {
  provider: string;
  indicator: string;
  indicatorType: IndicatorType;
  status: CTIStatus;
  riskScore?: number;
  confidence?: number;
  verdict: ThreatVerdict;
  queriedAt: string;
  latencyMs: number;
  retryable: boolean;
  provenance: string;
  rawResponse?: any;
}

export interface ThreatIntelligenceProvider {
  name: string;
  isAvailable(): Promise<boolean>;
  enrichDomain(domain: string): Promise<{ status: string; data?: any }>;
  enrichIp(ip: string): Promise<{ status: string; data?: any }>;
  enrichHash(hash: string): Promise<{ status: string; data?: any }>;
}

class RealRedisCache {
  private client: Redis | null = null;
  
  constructor() {
    if (process.env.REDIS_URL) {
      try {
        this.client = new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: 1, enableOfflineQueue: false });
        this.client.on('error', () => { /* swallow cache errors */ });
      } catch (e) {
        this.client = null;
      }
    }
  }

  async get(key: string): Promise<string | null> {
    if (!this.client) return null;
    try {
      return await this.client.get(key);
    } catch (e) {
      return null;
    }
  }

  async setex(key: string, ttl: number, val: string): Promise<void> {
    if (!this.client) return;
    try {
      await this.client.setex(key, ttl, val);
    } catch (e) {}
  }
}

/**
 * Narrow, dependency-free structural guard for the shape of error we can
 * receive from HttpClient's underlying axios request: either a real HTTP
 * response with a status code (`response.status`), a network-level axios
 * error code (e.g. 'ECONNABORTED' on timeout), or a plain Error thrown by
 * HttpClient's own SSRF guards (`validateUrl`/`safeLookup`) or by the
 * opossum circuit breaker ("Breaker is open") — none of which carry a
 * `response`. Avoids depending on axios's own types just for this check.
 */
interface HttpClientErrorShape {
  response?: { status?: number };
  code?: string;
  message?: string;
}

function asHttpClientError(e: unknown): HttpClientErrorShape {
  return typeof e === 'object' && e !== null ? (e as HttpClientErrorShape) : {};
}

export class ProductionCTILayer implements ThreatIntelligenceProvider {
  name = 'ProductionCTI_VT_AbuseIPDB';
  private redis = new RealRedisCache();
  private TTL = 3600;
  private TIMEOUT_MS = 5000;
  private readonly abuseIpdbClient: HttpClient;
  private readonly virusTotalClient: HttpClient;

  /**
   * Both CTI providers route through the existing SSRF-hardened
   * HttpClient (packages/http-client) rather than raw fetch(). Separate
   * named client instances per provider so a circuit-breaker trip on one
   * provider's outages can never fail-fast requests to the other.
   * Injectable for tests — production code always uses the defaults.
   */
  constructor(deps?: { abuseIpdbClient?: HttpClient; virusTotalClient?: HttpClient }) {
    this.abuseIpdbClient = deps?.abuseIpdbClient ?? new HttpClient('AbuseIPDB', { timeout: this.TIMEOUT_MS });
    this.virusTotalClient = deps?.virusTotalClient ?? new HttpClient('VirusTotal', { timeout: this.TIMEOUT_MS });
  }

  async isAvailable() { return true; }

  private async executeRequest(
    client: HttpClient,
    url: string,
    headers: Record<string, string>,
    providerName: string,
    indicator: string,
    type: IndicatorType
  ): Promise<CTINormalizedResult> {
    const start = Date.now();

    try {
      // HttpClient.get() already returns the parsed response body (axios
      // auto-parses JSON) and enforces SSRF protections (private/loopback/
      // link-local IP blocking, DNS-rebinding-safe lookup, protocol
      // allowlist, redirect re-validation, no embedded credentials) before
      // the request is ever sent — see packages/http-client/src/index.ts.
      const data = await client.get<any>(url, { headers });
      const latencyMs = Date.now() - start;

      // Basic normalization logic based on provider (unchanged)
      let verdict: ThreatVerdict = 'UNKNOWN';
      let confidence = 0;
      if (providerName === 'AbuseIPDB') {
        const score = data?.data?.abuseConfidenceScore || 0;
        if (score > 50) verdict = 'MALICIOUS';
        else if (score > 0) verdict = 'SUSPICIOUS';
        else verdict = 'CLEAN';
        confidence = score;
      } else if (providerName === 'VirusTotal') {
        const stats = data?.data?.attributes?.last_analysis_stats;
        if (stats) {
           if (stats.malicious > 0) verdict = 'MALICIOUS';
           else if (stats.suspicious > 0) verdict = 'SUSPICIOUS';
           else if (stats.harmless > 0 || stats.undetected > 0) verdict = 'CLEAN';
           const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
           confidence = total > 0 ? Math.round(((stats.malicious + stats.suspicious) / total) * 100) : 0;
        }
      }

      return {
          provider: providerName, indicator, indicatorType: type, status: 'available', verdict, confidence,
          queriedAt: new Date().toISOString(), latencyMs, retryable: false, provenance: 'API Integration'
      };

    } catch (rawError: unknown) {
      const latencyMs = Date.now() - start;
      const e = asHttpClientError(rawError);
      const status = e.response?.status;

      // Unlike fetch(), axios (which HttpClient wraps) rejects on any
      // non-2xx response rather than returning a response object with
      // .ok/.status — so the same 401/403/429/5xx classification that
      // used to read response.status now reads err.response.status.
      if (status === 401 || status === 403) {
        return {
          provider: providerName, indicator, indicatorType: type, status: 'unauthorized', verdict: 'UNKNOWN',
          queriedAt: new Date().toISOString(), latencyMs, retryable: false, provenance: 'API Integration'
        };
      }
      if (status === 429) {
        return {
          provider: providerName, indicator, indicatorType: type, status: 'rate_limited', verdict: 'UNKNOWN',
          queriedAt: new Date().toISOString(), latencyMs, retryable: true, provenance: 'API Integration'
        };
      }
      if (typeof status === 'number' && status >= 400) {
         return {
          provider: providerName, indicator, indicatorType: type, status: 'provider_error', verdict: 'UNKNOWN',
          queriedAt: new Date().toISOString(), latencyMs, retryable: status >= 500, provenance: 'API Integration'
        };
      }
      if (e.code === 'ECONNABORTED' || /timeout/i.test(e.message ?? '')) {
         return {
          provider: providerName, indicator, indicatorType: type, status: 'timeout', verdict: 'UNKNOWN',
          queriedAt: new Date().toISOString(), latencyMs, retryable: true, provenance: 'API Integration'
        };
      }
      // Catches everything else, including HttpClient's own SSRF-guard
      // rejections (e.g. "SSRF attempt blocked: ...") and an open
      // circuit breaker ("Breaker is open") — both are network-level
      // failures from the CTI caller's point of view, never surfaced as
      // fabricated threat-intel data.
      return {
          provider: providerName, indicator, indicatorType: type, status: 'unavailable', verdict: 'UNKNOWN',
          queriedAt: new Date().toISOString(), latencyMs, retryable: true, provenance: 'API Integration'
      };
    }
  }

  private async fetchExternal(indicator: string, type: IndicatorType): Promise<CTINormalizedResult> {
    if (type === 'IP') {
       const key = process.env.ABUSEIPDB_API_KEY;
       if (!key) {
         return { provider: 'AbuseIPDB', indicator, indicatorType: type, status: 'not_configured', verdict: 'UNKNOWN', queriedAt: new Date().toISOString(), latencyMs: 0, retryable: false, provenance: 'System' };
       }
       return this.executeRequest(this.abuseIpdbClient, `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(indicator)}`, { 'Key': key, 'Accept': 'application/json' }, 'AbuseIPDB', indicator, type);
    } else {
       // VirusTotal for domains and hashes
       const key = process.env.VIRUSTOTAL_API_KEY;
       if (!key) {
         return { provider: 'VirusTotal', indicator, indicatorType: type, status: 'not_configured', verdict: 'UNKNOWN', queriedAt: new Date().toISOString(), latencyMs: 0, retryable: false, provenance: 'System' };
       }
       const endpoint = type === 'DOMAIN' ? 'domains' : 'files';
       return this.executeRequest(this.virusTotalClient, `https://www.virustotal.com/api/v3/${endpoint}/${encodeURIComponent(indicator)}`, { 'x-apikey': key }, 'VirusTotal', indicator, type);
    }
  }

  private async withCacheAndRouter(indicator: string, type: IndicatorType) {
    if (!indicator) return { status: 'not_found' };
    
    const cacheKey = `cti:v1:${type}:${indicator}`;
    try {
      const cached = await this.redis.get(cacheKey);
      if (cached) {
         const parsed = JSON.parse(cached);
         // ensure cache hit adds a mark if needed
         parsed.fromCache = true;
         return { status: 'available', data: parsed };
      }
    } catch(e) {}

    const result = await this.fetchExternal(indicator, type);
    
    if (result.status === 'available') {
        try { await this.redis.setex(cacheKey, this.TTL, JSON.stringify(result)); } catch(e) {}
    }

    return { status: result.status, data: result };
  }

  async enrichDomain(domain: string): Promise<any> { return this.withCacheAndRouter(domain, 'DOMAIN'); }
  async enrichIp(ip: string): Promise<any> { return this.withCacheAndRouter(ip, 'IP'); }
  async enrichHash(hash: string): Promise<any> { return this.withCacheAndRouter(hash, 'HASH'); }
}

export const ctiProvider = new ProductionCTILayer();
