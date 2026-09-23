import { HttpClient } from '@ciperscope/http-client';
import { logger } from '@ciperscope/logger';

const IANA_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 5000;
const MAX_RESPONSE_BYTES = 1_000_000; // bound response size — never trust an unbounded external body

interface IanaBootstrap {
  // services: [[tlds...], [rdapBaseUrls...]][]
  services: Array<[string[], string[]]>;
}

interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, Array<[string, Record<string, unknown>, string, unknown]>];
}

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}

interface RdapNameserver {
  ldhName?: string;
}

export interface RawRdapDomainResponse {
  ldhName?: string;
  status?: string[];
  nameservers?: RdapNameserver[];
  entities?: RdapEntity[];
  events?: RdapEvent[];
}

export type RdapFetchResult =
  | { outcome: 'SUCCESS'; response: RawRdapDomainResponse; rdapSource: string }
  | { outcome: 'NOT_FOUND' }
  | { outcome: 'PROVIDER_TIMEOUT' }
  | { outcome: 'PROVIDER_ERROR'; errorMessage: string };

/**
 * Real RDAP protocol client — HTTPS only, IANA bootstrap-driven (no
 * hardcoded per-registry server list, no third-party RDAP redirector
 * service to add as a trust dependency). Reuses the existing SSRF-safe
 * `HttpClient` (DNS-rebinding protection, private-IP blocking, protocol
 * allowlist, redirect validation, circuit breaker) — never a bespoke fetch.
 */
export class RdapClient {
  private readonly http: HttpClient;
  private bootstrap: IanaBootstrap | null = null;
  private bootstrapFetchedAt = 0;

  constructor() {
    this.http = new HttpClient('rdap', { timeout: REQUEST_TIMEOUT_MS });
  }

  private async getBootstrap(): Promise<IanaBootstrap | null> {
    const isStale = Date.now() - this.bootstrapFetchedAt > BOOTSTRAP_TTL_MS;
    if (this.bootstrap && !isStale) return this.bootstrap;

    try {
      const data = await this.http.get<IanaBootstrap>(IANA_BOOTSTRAP_URL, {
        maxContentLength: MAX_RESPONSE_BYTES,
        maxBodyLength: MAX_RESPONSE_BYTES,
      });
      if (!data || !Array.isArray(data.services)) {
        throw new Error('Malformed IANA bootstrap response');
      }
      this.bootstrap = data;
      this.bootstrapFetchedAt = Date.now();
      return this.bootstrap;
    } catch (err) {
      logger.warn({ err: err instanceof Error ? err.message : err }, 'Failed to fetch IANA RDAP bootstrap registry');
      // Serve a stale-but-present bootstrap rather than nothing, if we have one.
      return this.bootstrap;
    }
  }

  private findRdapBaseUrls(bootstrap: IanaBootstrap, tld: string): string[] {
    const lower = tld.toLowerCase();
    for (const [tlds, urls] of bootstrap.services) {
      if (tlds.some((t) => t.toLowerCase() === lower)) return urls;
    }
    return [];
  }

  public async fetchDomain(registrableDomain: string): Promise<RdapFetchResult> {
    const labels = registrableDomain.split('.');
    const tld = labels[labels.length - 1];
    if (!tld) return { outcome: 'PROVIDER_ERROR', errorMessage: 'Cannot determine TLD' };

    const bootstrap = await this.getBootstrap();
    if (!bootstrap) return { outcome: 'PROVIDER_ERROR', errorMessage: 'RDAP bootstrap registry unavailable' };

    const baseUrls = this.findRdapBaseUrls(bootstrap, tld);
    if (baseUrls.length === 0) {
      return { outcome: 'PROVIDER_ERROR', errorMessage: `No RDAP server registered for TLD .${tld}` };
    }

    let lastError: string | null = null;
    for (const base of baseUrls) {
      const url = `${base.endsWith('/') ? base : `${base}/`}domain/${registrableDomain}`;
      try {
        const response = await this.http.get<RawRdapDomainResponse>(url, {
          maxContentLength: MAX_RESPONSE_BYTES,
          maxBodyLength: MAX_RESPONSE_BYTES,
          headers: { accept: 'application/rdap+json' },
        });
        return { outcome: 'SUCCESS', response, rdapSource: base };
      } catch (err) {
        const status = (err as { response?: { status?: number } })?.response?.status;
        if (status === 404) return { outcome: 'NOT_FOUND' };
        const message = err instanceof Error ? err.message : 'Unknown RDAP error';
        if (/timeout/i.test(message)) return { outcome: 'PROVIDER_TIMEOUT' };
        lastError = message;
        // Try the next base URL for this TLD before giving up.
      }
    }
    return { outcome: 'PROVIDER_ERROR', errorMessage: lastError ?? 'All RDAP servers for this TLD failed' };
  }
}
