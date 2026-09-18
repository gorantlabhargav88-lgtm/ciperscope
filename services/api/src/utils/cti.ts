export type CTIStatus = 'available' | 'unavailable' | 'degraded' | 'not_found' | 'rate_limited' | 'unauthorized' | 'timeout' | 'provider_error';

export interface CTIResponse {
  status: CTIStatus;
  data?: any;
  provider?: string;
  queriedAt?: string;
  latencyMs?: number;
}

export interface ThreatIntelligenceProvider {
  name: string;
  isAvailable(): Promise<boolean>;
  enrichDomain(domain: string): Promise<CTIResponse>;
  enrichIp(ip: string): Promise<CTIResponse>;
  enrichHash(hash: string): Promise<CTIResponse>;
}

export class ResilientCTIProvider implements ThreatIntelligenceProvider {
  name = 'Mock_Resilient_CTI';
  
  async isAvailable() {
    return true; 
  }

  private async withResiliency<T>(operation: () => Promise<T>, fallback: T): Promise<T> {
    const timeout = new Promise<T>((resolve) => setTimeout(() => resolve(fallback), 5000));
    try {
      return await Promise.race([operation(), timeout]);
    } catch (e) {
      return fallback;
    }
  }

  async enrichDomain(domain: string): Promise<CTIResponse> {
    return this.withResiliency(async () => {
      const start = Date.now();
      if (!domain) return { status: 'not_found', provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
      
      if (domain.includes('timeout')) {
          await new Promise(resolve => setTimeout(resolve, 6000)); // will trigger timeout fallback
      }
      
      if (domain.includes('malicious') || domain.includes('phishing')) {
        return { status: 'available', data: { malicious_votes: 45, threat_category: 'phishing' }, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
      }
      return { status: 'available', data: { malicious_votes: 0, threat_category: 'benign' }, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
    }, { status: 'timeout' as CTIStatus, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: 5000 });
  }

  async enrichIp(ip: string): Promise<CTIResponse> {
    return this.withResiliency(async () => {
      const start = Date.now();
      if (ip === '8.8.8.8') return { status: 'available', data: { malicious_votes: 0 }, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
      if (ip === '1.2.3.4') return { status: 'available', data: { malicious_votes: 20, abuse_score: 95 }, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
      return { status: 'not_found', provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
    }, { status: 'timeout' as CTIStatus, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: 5000 });
  }

  async enrichHash(hash: string): Promise<CTIResponse> {
    return this.withResiliency(async () => {
      const start = Date.now();
      if (hash === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') {
         return { status: 'available', data: { malicious_votes: 0 }, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
      }
      return { status: 'available', data: { malicious_votes: 12, threat_label: 'trojan' }, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
    }, { status: 'timeout' as CTIStatus, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: 5000 });
  }
}

export const ctiProvider = new ResilientCTIProvider();
