export interface ThreatIntelligenceProvider {
  name: string;
  isAvailable(): Promise<boolean>;
  enrichDomain(domain: string): Promise<{ status: 'available' | 'unavailable' | 'degraded' | 'not_found'; data?: any }>;
  enrichIp(ip: string): Promise<{ status: 'available' | 'unavailable' | 'degraded' | 'not_found'; data?: any }>;
  enrichHash(hash: string): Promise<{ status: 'available' | 'unavailable' | 'degraded' | 'not_found'; data?: any }>;
}

export class ResilientCTIProvider implements ThreatIntelligenceProvider {
  name = 'Mock_Resilient_CTI';
  
  async isAvailable() {
    return true; 
  }

  private simulateNetworkDelay() {
    // Return resolved promise to keep tests fast, but in real world this would have timeout/retry semantics
    return Promise.resolve();
  }

  async enrichDomain(domain: string): Promise<any> {
    await this.simulateNetworkDelay();
    if (!domain) return { status: 'not_found' };
    
    // Deterministic mock logic based on input
    if (domain.includes('malicious') || domain.includes('phishing')) {
      return { status: 'available', data: { malicious_votes: 45, threat_category: 'phishing' } };
    }
    return { status: 'available', data: { malicious_votes: 0, threat_category: 'benign' } };
  }

  async enrichIp(ip: string): Promise<any> {
    await this.simulateNetworkDelay();
    if (ip === '8.8.8.8') return { status: 'available', data: { malicious_votes: 0 } };
    if (ip === '1.2.3.4') return { status: 'available', data: { malicious_votes: 20, abuse_score: 95 } };
    return { status: 'not_found' };
  }

  async enrichHash(hash: string): Promise<any> {
    await this.simulateNetworkDelay();
    if (hash === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') {
       return { status: 'available', data: { malicious_votes: 0 } }; // Empty SHA256
    }
    return { status: 'available', data: { malicious_votes: 12, threat_label: 'trojan' } };
  }
}

export const ctiProvider = new ResilientCTIProvider();
