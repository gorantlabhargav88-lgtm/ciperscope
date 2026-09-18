import { Redis } from 'ioredis';

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

export class ProductionCTILayer implements ThreatIntelligenceProvider {
  name = 'ProductionCTI_VT_AbuseIPDB';
  private redis = new RealRedisCache();
  private TTL = 3600;
  private TIMEOUT_MS = 5000;

  async isAvailable() { return true; }

  private async executeFetch(
    url: string, 
    headers: Record<string, string>, 
    providerName: string, 
    indicator: string, 
    type: IndicatorType
  ): Promise<CTINormalizedResult> {
    const start = Date.now();
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), this.TIMEOUT_MS);

    try {
      const response = await fetch(url, { headers, signal: controller.signal });
      clearTimeout(id);
      
      const latencyMs = Date.now() - start;

      if (response.status === 401 || response.status === 403) {
        return {
          provider: providerName, indicator, indicatorType: type, status: 'unauthorized', verdict: 'UNKNOWN',
          queriedAt: new Date().toISOString(), latencyMs, retryable: false, provenance: 'API Integration'
        };
      }
      if (response.status === 429) {
        return {
          provider: providerName, indicator, indicatorType: type, status: 'rate_limited', verdict: 'UNKNOWN',
          queriedAt: new Date().toISOString(), latencyMs, retryable: true, provenance: 'API Integration'
        };
      }
      if (!response.ok) {
         return {
          provider: providerName, indicator, indicatorType: type, status: 'provider_error', verdict: 'UNKNOWN',
          queriedAt: new Date().toISOString(), latencyMs, retryable: response.status >= 500, provenance: 'API Integration'
        };
      }

      const data = await response.json();
      
      // Basic normalization logic based on provider
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

    } catch (e: any) {
      clearTimeout(id);
      const latencyMs = Date.now() - start;
      if (e.name === 'AbortError') {
         return {
          provider: providerName, indicator, indicatorType: type, status: 'timeout', verdict: 'UNKNOWN',
          queriedAt: new Date().toISOString(), latencyMs, retryable: true, provenance: 'API Integration'
        };
      }
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
       return this.executeFetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(indicator)}`, { 'Key': key, 'Accept': 'application/json' }, 'AbuseIPDB', indicator, type);
    } else {
       // VirusTotal for domains and hashes
       const key = process.env.VIRUSTOTAL_API_KEY;
       if (!key) {
         return { provider: 'VirusTotal', indicator, indicatorType: type, status: 'not_configured', verdict: 'UNKNOWN', queriedAt: new Date().toISOString(), latencyMs: 0, retryable: false, provenance: 'System' };
       }
       const endpoint = type === 'DOMAIN' ? 'domains' : 'files';
       return this.executeFetch(`https://www.virustotal.com/api/v3/${endpoint}/${encodeURIComponent(indicator)}`, { 'x-apikey': key }, 'VirusTotal', indicator, type);
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
