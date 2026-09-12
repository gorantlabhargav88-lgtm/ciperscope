import { DnsResolver } from './DnsResolver';
import { AuthResultStatus } from '@ciperscope/database';
import * as ipaddr from 'ipaddr.js';

export interface SpfResult {
  result: AuthResultStatus;
  domain: string;
  evaluatedIp: string;
  matchedMechanism: string | null;
  explanation: string;
}

export class SpfVerifier {
  constructor(private resolver: DnsResolver) {}

  public async verify(domain: string, ip: string): Promise<SpfResult> {
    try {
      return await this.evaluateDomain(domain, ip, domain, 0);
    } catch (err: unknown) {
      const error = err as Error;
      if (error.message === 'DNS_TIMEOUT') {
        return { result: 'TEMPERROR', domain, evaluatedIp: ip, matchedMechanism: null, explanation: 'DNS timeout' };
      }
      if (error.message.includes('limit exceeded')) {
        return { result: 'PERMERROR', domain, evaluatedIp: ip, matchedMechanism: null, explanation: 'DNS lookup limit exceeded' };
      }
      return { result: 'PERMERROR', domain, evaluatedIp: ip, matchedMechanism: null, explanation: error.message };
    }
  }

  private async evaluateDomain(domain: string, ip: string, originalDomain: string, depth: number): Promise<SpfResult> {
    // 1. Fetch TXT records
    const txtRecords = await this.resolver.resolveTxt(domain);
    
    // 2. Filter for SPF
    const spfRecords = txtRecords.filter(r => r === 'v=spf1' || r.startsWith('v=spf1 '));
    
    if (spfRecords.length === 0) {
      return { result: 'NONE', domain: originalDomain, evaluatedIp: ip, matchedMechanism: null, explanation: `No SPF record found for ${domain}` };
    }
    
    if (spfRecords.length > 1) {
      return { result: 'PERMERROR', domain: originalDomain, evaluatedIp: ip, matchedMechanism: null, explanation: `Multiple SPF records found for ${domain}` };
    }

    const record = spfRecords[0];
    const terms = record.split(/\s+/).slice(1).filter(t => t.length > 0);

    for (const term of terms) {
      // Modifiers (e.g., redirect=, exp=)
      if (term.includes('=')) {
        const [modifier, value] = term.split('=');
        if (modifier.toLowerCase() === 'redirect') {
          return await this.evaluateDomain(value, ip, originalDomain, depth + 1);
        }
        continue;
      }

      // Mechanisms
      let qualifier = '+';
      let mechanism = term;
      
      if (['+', '-', '~', '?'].includes(term[0])) {
        qualifier = term[0];
        mechanism = term.slice(1);
      }

      const lowerMech = mechanism.toLowerCase();
      let isMatch = false;

      if (lowerMech === 'all') {
        isMatch = true;
      } else if (lowerMech.startsWith('ip4:')) {
        isMatch = this.matchIp(ip, mechanism.slice(4), 'ipv4');
      } else if (lowerMech.startsWith('ip6:')) {
        isMatch = this.matchIp(ip, mechanism.slice(4), 'ipv6');
      } else if (lowerMech.startsWith('include:')) {
        const includeDomain = mechanism.slice(8);
        const includeResult = await this.evaluateDomain(includeDomain, ip, originalDomain, depth + 1);
        if (includeResult.result === 'PASS') {
          isMatch = true;
        } else if (includeResult.result === 'PERMERROR' || includeResult.result === 'TEMPERROR') {
          return includeResult;
        }
      } else if (lowerMech === 'a' || lowerMech.startsWith('a:') || lowerMech.startsWith('a/')) {
        isMatch = await this.matchA(domain, ip, mechanism);
      } else if (lowerMech === 'mx' || lowerMech.startsWith('mx:') || lowerMech.startsWith('mx/')) {
        isMatch = await this.matchMx(domain, ip, mechanism);
      } else if (lowerMech.startsWith('exists:')) {
        const existsDomain = mechanism.slice(7);
        const aRecs = await this.resolver.resolveA(existsDomain);
        isMatch = aRecs.length > 0;
      }

      if (isMatch) {
        let result: AuthResultStatus = 'PASS';
        if (qualifier === '-') result = 'FAIL';
        else if (qualifier === '~') result = 'SOFTFAIL';
        else if (qualifier === '?') result = 'NEUTRAL';
        
        return {
          result,
          domain: originalDomain,
          evaluatedIp: ip,
          matchedMechanism: term,
          explanation: `Matched mechanism: ${term}`
        };
      }
    }

    // Default return neutral if no matches
    return {
      result: 'NEUTRAL',
      domain: originalDomain,
      evaluatedIp: ip,
      matchedMechanism: null,
      explanation: 'No mechanism matched'
    };
  }

  private matchIp(ip: string, cidrOrIp: string, expectedKind: 'ipv4' | 'ipv6'): boolean {
    try {
      const parsedIp = ipaddr.parse(ip);
      if (parsedIp.kind() !== expectedKind) return false;
      
      if (cidrOrIp.includes('/')) {
        const [netIp, prefixLen] = cidrOrIp.split('/');
        const parsedNet = ipaddr.parse(netIp);
        const cidr = ipaddr.parseCIDR(`${parsedNet.toString()}/${prefixLen}`);
        return parsedIp.match(cidr);
      } else {
        const parsedTarget = ipaddr.parse(cidrOrIp);
        return parsedIp.toString() === parsedTarget.toString();
      }
    } catch {
      return false;
    }
  }

  private async matchA(defaultDomain: string, ip: string, mechanism: string): Promise<boolean> {
    const parsedIp = ipaddr.parse(ip);
    
    let targetDomain = defaultDomain;
    let cidr = parsedIp.kind() === 'ipv4' ? 32 : 128;
    
    const parts = mechanism.split('/');
    const target = parts[0];
    
    if (target.startsWith('a:')) {
      targetDomain = target.slice(2);
    }
    
    if (parts.length > 1) {
      // Very basic handling, assuming ipv4 cidr for simplicity in this implementation
      cidr = parseInt(parts[1], 10);
    }

    const records = parsedIp.kind() === 'ipv4' 
      ? await this.resolver.resolveA(targetDomain)
      : await this.resolver.resolveAaaa(targetDomain);
      
    for (const record of records) {
      if (this.matchIp(ip, `${record}/${cidr}`, parsedIp.kind() as 'ipv4'|'ipv6')) {
        return true;
      }
    }
    return false;
  }

  private async matchMx(defaultDomain: string, ip: string, mechanism: string): Promise<boolean> {
    const parsedIp = ipaddr.parse(ip);
    
    let targetDomain = defaultDomain;
    let cidr = parsedIp.kind() === 'ipv4' ? 32 : 128;
    
    const parts = mechanism.split('/');
    const target = parts[0];
    
    if (target.startsWith('mx:')) {
      targetDomain = target.slice(3);
    }
    
    if (parts.length > 1) {
      cidr = parseInt(parts[1], 10);
    }

    const mxRecords = await this.resolver.resolveMx(targetDomain);
    
    for (const mx of mxRecords) {
      const records = parsedIp.kind() === 'ipv4' 
        ? await this.resolver.resolveA(mx.exchange)
        : await this.resolver.resolveAaaa(mx.exchange);
        
      for (const record of records) {
        if (this.matchIp(ip, `${record}/${cidr}`, parsedIp.kind() as 'ipv4'|'ipv6')) {
          return true;
        }
      }
    }
    return false;
  }
}
