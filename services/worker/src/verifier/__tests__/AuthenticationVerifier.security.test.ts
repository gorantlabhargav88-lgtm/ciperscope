import { DnsResolver } from '../DnsResolver';
import { SpfVerifier } from '../SpfVerifier';
import dns from 'dns/promises';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import fs from 'fs';
import path from 'path';

vi.mock('dns/promises');

describe('Security: Authentication Verifiers', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe('DnsResolver Limits', () => {
    it('should strictly enforce maximum DNS lookups to prevent recursion exhaustion (DoS)', async () => {
      const resolver = new DnsResolver(3, 1000); // Max 3 lookups
      const spfVerifier = new SpfVerifier(resolver);

      // Setup a cyclic or deeply recursive SPF chain
      // a.com -> include:b.com -> include:c.com -> include:d.com -> include:e.com
      vi.mocked(dns.resolveTxt).mockImplementation(async (domain: string) => {
        if (domain === 'a.com') return [['v=spf1 include:b.com ~all']];
        if (domain === 'b.com') return [['v=spf1 include:c.com ~all']];
        if (domain === 'c.com') return [['v=spf1 include:d.com ~all']];
        if (domain === 'd.com') return [['v=spf1 include:e.com ~all']];
        return [['v=spf1 -all']];
      });

      const result = await spfVerifier.verify('a.com', '192.168.1.1');
      
      // Since max lookups is 3, it should fail at c.com -> d.com
      expect(result.result).toBe('PERMERROR');
      expect(result.explanation).toContain('DNS lookup limit exceeded');
      expect(resolver.getLookupCount()).toBe(4); // Exceeded on the 4th call
    });

    it('should handle DNS timeouts gracefully as TEMPERROR without hanging', async () => {
      const resolver = new DnsResolver(10, 50); // 50ms timeout
      const spfVerifier = new SpfVerifier(resolver);

      vi.mocked(dns.resolveTxt).mockImplementation(async () => {
        return new Promise(resolve => setTimeout(resolve, 200)); // 200ms delay, exceeds 50ms
      });

      const start = Date.now();
      const result = await spfVerifier.verify('timeout.com', '192.168.1.1');
      const duration = Date.now() - start;

      expect(result.result).toBe('TEMPERROR');
      expect(result.explanation).toContain('DNS timeout');
      expect(duration).toBeLessThan(150); // Should resolve quickly due to 50ms timeout
    });
  });

  describe('SSRF / Network Protections', () => {
    it('must NEVER use http/fetch or open arbitrary sockets in verifiers', () => {
      // Static code analysis: ensure fetch/axios is not imported or used
      // Dynamic requires removed in favor of top-level imports
      
      const filesToCheck = [
        'AuthenticationVerifier.ts',
        'DnsResolver.ts',
        'SpfVerifier.ts',
        'DkimVerifier.ts',
        'DmarcVerifier.ts'
      ];

      for (const file of filesToCheck) {
        const content = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
        expect(content).not.toMatch(/require\(['"](http|https|axios|node-fetch)['"]\)/);
        expect(content).not.toMatch(/from\s+['"](http|https|axios|node-fetch)['"]/);
        // Ensure no global fetch is used
        expect(content).not.toMatch(/\Wfetch\(/);
      }
    });
  });
});
