import dns from 'dns/promises';

export interface DnsObservationRecord {
  queryName: string;
  recordType: string;
  response: string | null;
  rcode: string;
  durationMs: number;
}

export class DnsResolver {
  private cache = new Map<string, unknown>();
  private lookupCount = 0;
  private readonly MAX_LOOKUPS: number;
  private readonly DEFAULT_TIMEOUT_MS: number;
  private observations: DnsObservationRecord[] = [];

  constructor(
    maxLookups: number = 50,
    timeoutMs: number = 2000
  ) {
    this.MAX_LOOKUPS = maxLookups;
    this.DEFAULT_TIMEOUT_MS = timeoutMs;
  }

  public getObservations(): DnsObservationRecord[] {
    return this.observations;
  }

  public getLookupCount(): number {
    return this.lookupCount;
  }

  private incrementLookup() {
    this.lookupCount++;
    if (this.lookupCount > this.MAX_LOOKUPS) {
      throw new Error(`DNS Lookup limit exceeded (${this.MAX_LOOKUPS})`);
    }
  }

  private async withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
    let timeoutId: NodeJS.Timeout;
    const timeout = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => reject(new Error('DNS_TIMEOUT')), ms);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timeoutId));
  }

  private recordObservation(
    queryName: string,
    recordType: string,
    response: string | null,
    rcode: string,
    durationMs: number
  ) {
    this.observations.push({ queryName, recordType, response, rcode, durationMs });
  }

  public async resolveTxt(domain: string): Promise<string[]> {
    this.incrementLookup();
    const cacheKey = `TXT:${domain}`;
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey) as string[];
    }

    const start = Date.now();
    try {
      // dns.resolveTxt returns string[][]
      const records = await this.withTimeout(dns.resolveTxt(domain), this.DEFAULT_TIMEOUT_MS);
      // Flatten the array of arrays and join chunks (a single TXT record can be split into multiple strings)
      const joinedRecords = records.map(chunks => chunks.join(''));
      
      const duration = Date.now() - start;
      this.recordObservation(domain, 'TXT', JSON.stringify(joinedRecords), 'NOERROR', duration);
      
      this.cache.set(cacheKey, joinedRecords);
      return joinedRecords;
    } catch (err: unknown) {
      const duration = Date.now() - start;
      const error = err as { code?: string; message?: string };
      const code = error.code || error.message || 'UNKNOWN';
      this.recordObservation(domain, 'TXT', null, code, duration);
      
      if (code === 'ENOTFOUND' || code === 'ENODATA') {
        this.cache.set(cacheKey, []);
        return [];
      }
      throw err;
    }
  }

  public async resolveA(domain: string): Promise<string[]> {
    this.incrementLookup();
    const cacheKey = `A:${domain}`;
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey) as string[];
    }

    const start = Date.now();
    try {
      const records = await this.withTimeout(dns.resolve4(domain), this.DEFAULT_TIMEOUT_MS);
      const duration = Date.now() - start;
      this.recordObservation(domain, 'A', JSON.stringify(records), 'NOERROR', duration);
      
      this.cache.set(cacheKey, records);
      return records;
    } catch (err: unknown) {
      const duration = Date.now() - start;
      const error = err as { code?: string; message?: string };
      const code = error.code || error.message || 'UNKNOWN';
      this.recordObservation(domain, 'A', null, code, duration);
      
      if (code === 'ENOTFOUND' || code === 'ENODATA') {
        this.cache.set(cacheKey, []);
        return [];
      }
      throw err;
    }
  }

  public async resolveAaaa(domain: string): Promise<string[]> {
    this.incrementLookup();
    const cacheKey = `AAAA:${domain}`;
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey) as string[];
    }

    const start = Date.now();
    try {
      const records = await this.withTimeout(dns.resolve6(domain), this.DEFAULT_TIMEOUT_MS);
      const duration = Date.now() - start;
      this.recordObservation(domain, 'AAAA', JSON.stringify(records), 'NOERROR', duration);
      
      this.cache.set(cacheKey, records);
      return records;
    } catch (err: unknown) {
      const duration = Date.now() - start;
      const error = err as { code?: string; message?: string };
      const code = error.code || error.message || 'UNKNOWN';
      this.recordObservation(domain, 'AAAA', null, code, duration);
      
      if (code === 'ENOTFOUND' || code === 'ENODATA') {
        this.cache.set(cacheKey, []);
        return [];
      }
      throw err;
    }
  }

  /** Reverse DNS (PTR) lookup for an IP address. Purely informational
   *  forensic context (e.g. "does this relay IP have a PTR record, and
   *  what does it claim to be") — the result is attacker-influenceable
   *  (anyone can set up a PTR record) and must never be treated as a
   *  verified identity, only as an additional data point alongside
   *  Received-header parsing and CTI/geo results. */
  public async resolvePtr(ip: string): Promise<string[]> {
    this.incrementLookup();
    const cacheKey = `PTR:${ip}`;
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey) as string[];
    }

    const start = Date.now();
    try {
      const records = await this.withTimeout(dns.reverse(ip), this.DEFAULT_TIMEOUT_MS);
      const duration = Date.now() - start;
      this.recordObservation(ip, 'PTR', JSON.stringify(records), 'NOERROR', duration);

      this.cache.set(cacheKey, records);
      return records;
    } catch (err: unknown) {
      const duration = Date.now() - start;
      const error = err as { code?: string; message?: string };
      const code = error.code || error.message || 'UNKNOWN';
      this.recordObservation(ip, 'PTR', null, code, duration);

      if (code === 'ENOTFOUND' || code === 'ENODATA') {
        this.cache.set(cacheKey, []);
        return [];
      }
      throw err;
    }
  }

  public async resolveMx(domain: string): Promise<{ exchange: string; priority: number }[]> {
    this.incrementLookup();
    const cacheKey = `MX:${domain}`;
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey) as { exchange: string; priority: number }[];
    }

    const start = Date.now();
    try {
      const records = await this.withTimeout(dns.resolveMx(domain), this.DEFAULT_TIMEOUT_MS);
      // Sort by priority
      records.sort((a, b) => a.priority - b.priority);
      
      const duration = Date.now() - start;
      this.recordObservation(domain, 'MX', JSON.stringify(records), 'NOERROR', duration);
      
      this.cache.set(cacheKey, records);
      return records;
    } catch (err: unknown) {
      const duration = Date.now() - start;
      const error = err as { code?: string; message?: string };
      const code = error.code || error.message || 'UNKNOWN';
      this.recordObservation(domain, 'MX', null, code, duration);
      
      if (code === 'ENOTFOUND' || code === 'ENODATA') {
        this.cache.set(cacheKey, []);
        return [];
      }
      throw err;
    }
  }
}
