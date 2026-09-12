import { DnsResolver } from './DnsResolver';
import { AuthResultStatus } from '@ciperscope/database';
import psl from 'psl';

export interface DmarcResult {
  result: AuthResultStatus;
  orgDomain: string | null;
  policy: string | null;
  subdomainPolicy: string | null;
  spfAlignment: string | null;
  dkimAlignment: string | null;
  explanation: string;
}

export class DmarcVerifier {
  constructor(private resolver: DnsResolver) {}

  public getOrganizationalDomain(domain: string): string | null {
    const parsed = psl.parse(domain);
    if ('error' in parsed || !('domain' in parsed) || !parsed.domain) {
      return null;
    }
    return parsed.domain;
  }

  public async verify(
    headerFromDomain: string,
    spfDomain: string | null,
    spfResult: AuthResultStatus,
    dkimDomain: string | null,
    dkimResult: AuthResultStatus
  ): Promise<DmarcResult> {
    const orgDomain = this.getOrganizationalDomain(headerFromDomain);
    
    if (!orgDomain) {
      return {
        result: 'PERMERROR',
        orgDomain: null,
        policy: null,
        subdomainPolicy: null,
        spfAlignment: 'unaligned',
        dkimAlignment: 'unaligned',
        explanation: `Invalid Header From domain: ${headerFromDomain}`
      };
    }

    try {
      // Look up DMARC on the exact domain
      let dmarcRecords = await this.resolver.resolveTxt(`_dmarc.${headerFromDomain}`);
      // If no DMARC record on exact domain, fallback to org domain (if different)
      if (dmarcRecords.length === 0 && headerFromDomain !== orgDomain) {
        dmarcRecords = await this.resolver.resolveTxt(`_dmarc.${orgDomain}`);
      }

      const validDmarcRecords = dmarcRecords.filter(r => r.startsWith('v=DMARC1'));
      
      if (validDmarcRecords.length === 0) {
        return {
          result: 'NONE',
          orgDomain,
          policy: null,
          subdomainPolicy: null,
          spfAlignment: 'unaligned',
          dkimAlignment: 'unaligned',
          explanation: 'No DMARC record found'
        };
      }
      
      if (validDmarcRecords.length > 1) {
        return {
          result: 'PERMERROR',
          orgDomain,
          policy: null,
          subdomainPolicy: null,
          spfAlignment: 'unaligned',
          dkimAlignment: 'unaligned',
          explanation: 'Multiple DMARC records found'
        };
      }

      const record = validDmarcRecords[0];
      const params = this.parseDmarcRecord(record);
      
      const p = params.get('p') || 'none';
      const sp = params.get('sp') || p;
      const adkim = params.get('adkim') || 'r';
      const aspf = params.get('aspf') || 'r';

      // Check alignments
      const isSpfAligned = this.checkAlignment(headerFromDomain, orgDomain, spfDomain, aspf);
      const isDkimAligned = this.checkAlignment(headerFromDomain, orgDomain, dkimDomain, adkim);

      const spfPasses = spfResult === 'PASS' && isSpfAligned;
      const dkimPasses = dkimResult === 'PASS' && isDkimAligned;

      const dmarcPasses = spfPasses || dkimPasses;

      return {
        result: dmarcPasses ? 'PASS' : 'FAIL',
        orgDomain,
        policy: p,
        subdomainPolicy: sp !== p ? sp : null,
        spfAlignment: isSpfAligned ? (aspf === 's' ? 'strict' : 'relaxed') : 'unaligned',
        dkimAlignment: isDkimAligned ? (adkim === 's' ? 'strict' : 'relaxed') : 'unaligned',
        explanation: dmarcPasses 
          ? `DMARC pass (SPF aligned: ${spfPasses}, DKIM aligned: ${dkimPasses})`
          : `DMARC fail (SPF aligned: ${spfPasses}, DKIM aligned: ${dkimPasses})`
      };

    } catch (err: unknown) {
      if ((err as Error).message === 'DNS_TIMEOUT') {
        return {
          result: 'TEMPERROR',
          orgDomain,
          policy: null,
          subdomainPolicy: null,
          spfAlignment: 'unaligned',
          dkimAlignment: 'unaligned',
          explanation: 'DNS timeout fetching DMARC record'
        };
      }
      return {
        result: 'PERMERROR',
        orgDomain,
        policy: null,
        subdomainPolicy: null,
        spfAlignment: 'unaligned',
        dkimAlignment: 'unaligned',
        explanation: `Verification error: ${(err as Error).message}`
      };
    }
  }

  private checkAlignment(headerFrom: string, headerFromOrg: string, authDomain: string | null, mode: string): boolean {
    if (!authDomain) return false;
    
    // Strict alignment: exact match
    if (mode === 's') {
      return headerFrom.toLowerCase() === authDomain.toLowerCase();
    }
    
    // Relaxed alignment: organizational domain match
    const authOrg = this.getOrganizationalDomain(authDomain);
    if (!authOrg) return false;
    
    return headerFromOrg.toLowerCase() === authOrg.toLowerCase();
  }

  private parseDmarcRecord(record: string): Map<string, string> {
    const params = new Map<string, string>();
    const parts = record.split(';');
    for (const part of parts) {
      const splitIndex = part.indexOf('=');
      if (splitIndex > 0) {
        const key = part.slice(0, splitIndex).trim().toLowerCase();
        const value = part.slice(splitIndex + 1).trim().toLowerCase();
        params.set(key, value);
      }
    }
    return params;
  }
}
