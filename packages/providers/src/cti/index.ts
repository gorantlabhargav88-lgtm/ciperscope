export interface ThreatIntelligenceProvider {
  name: string;
  isAvailable(): Promise<boolean>;
  enrichDomain(domain: string): Promise<CTIResponse>;
  enrichIp(ip: string): Promise<CTIResponse>;
  enrichHash(hash: string): Promise<CTIResponse>;
}

export type CTIStatus = 'available' | 'unavailable' | 'degraded' | 'not_found' | 'rate_limited' | 'unauthorized' | 'timeout' | 'provider_error';

export interface CTIResponse {
  status: CTIStatus;
  data?: any;
  provider: string;
  queriedAt: string;
  latencyMs?: number;
}

export class MockCTIProvider implements ThreatIntelligenceProvider {
  name = 'Mock_Resilient_CTI';
  
  async isAvailable() {
    return true; 
  }

  private async simulateNetworkDelay() {
    return new Promise(resolve => setTimeout(resolve, 10));
  }

  async enrichDomain(domain: string): Promise<CTIResponse> {
    const start = Date.now();
    await this.simulateNetworkDelay();
    if (!domain) return { status: 'not_found', provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
    
    if (domain.includes('timeout')) return { status: 'timeout', provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
    if (domain.includes('ratelimit')) return { status: 'rate_limited', provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };

    if (domain.includes('malicious') || domain.includes('phishing')) {
      return { status: 'available', data: { malicious_votes: 45, threat_category: 'phishing' }, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
    }
    return { status: 'available', data: { malicious_votes: 0, threat_category: 'benign' }, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
  }

  async enrichIp(ip: string): Promise<CTIResponse> {
    const start = Date.now();
    await this.simulateNetworkDelay();
    if (ip === '8.8.8.8') return { status: 'available', data: { malicious_votes: 0 }, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
    if (ip === '1.2.3.4') return { status: 'available', data: { malicious_votes: 20, abuse_score: 95 }, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
    return { status: 'not_found', provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
  }

  async enrichHash(hash: string): Promise<CTIResponse> {
    const start = Date.now();
    await this.simulateNetworkDelay();
    if (hash === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') {
       return { status: 'available', data: { malicious_votes: 0 }, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
    }
    return { status: 'available', data: { malicious_votes: 12, threat_label: 'trojan' }, provider: this.name, queriedAt: new Date().toISOString(), latencyMs: Date.now() - start };
  }
}
