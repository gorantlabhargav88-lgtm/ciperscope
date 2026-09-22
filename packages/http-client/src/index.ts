import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import CircuitBreaker from 'opossum';
import http from 'http';
import https from 'https';
import dns from 'dns';
import net from 'net';

export interface HttpClientOptions {
  baseURL?: string;
  timeout?: number;
  circuitBreakerOptions?: CircuitBreaker.Options;
}

export function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 0) return true; // 0.0.0.0/8
    if (parts[0] === 10) return true; // 10.0.0.0/8
    if (parts[0] === 127) return true; // 127.0.0.0/8 loopback
    if (parts[0] === 169 && parts[1] === 254) return true; // 169.254.0.0/16 link-local
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
    if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16
  } else if (net.isIPv6(ip)) {
    const ipLower = ip.toLowerCase();
    if (ipLower === '::1') return true; // ::1 loopback
    if (ipLower === '::') return true; // :: unspecified
    if (ipLower.startsWith('fe80:')) return true; // fe80::/10 link-local
    if (ipLower.startsWith('fc') || ipLower.startsWith('fd')) return true; // fc00::/7 unique local
    
    // IPv4-mapped IPv6 address: ::ffff:127.0.0.1 or ::ffff:7f00:1
    if (ipLower.startsWith('::ffff:')) {
      const v4Part = ipLower.substring(7);
      if (v4Part.includes('.')) {
        return isPrivateIp(v4Part);
      } else {
        // Hex representation ::ffff:7f00:1
        const hexSegments = v4Part.split(':');
        if (hexSegments.length === 2) {
          const hex = hexSegments[0].padStart(4, '0') + hexSegments[1].padStart(4, '0');
          const p1 = parseInt(hex.substring(0, 2), 16);
          const p2 = parseInt(hex.substring(2, 4), 16);
          const p3 = parseInt(hex.substring(4, 6), 16);
          const p4 = parseInt(hex.substring(6, 8), 16);
          return isPrivateIp(`${p1}.${p2}.${p3}.${p4}`);
        }
      }
    }
  }
  return false;
}

export type IpVersion = 'v4' | 'v6' | null;

export type IpCategory =
  | 'PRIVATE'
  | 'LOOPBACK'
  | 'LINK_LOCAL'
  | 'MULTICAST'
  | 'DOCUMENTATION'
  | 'RESERVED'
  | 'PUBLIC'
  | 'INVALID';

export interface IpClassification {
  ip: string;
  version: IpVersion;
  category: IpCategory;
  /** True for anything callers must never send to an external
   *  GeoIP/reputation provider (private/loopback/link-local/reserved/etc). */
  isRoutablePublic: boolean;
}

// RFC 5737 (TEST-NET-1/2/3) documentation ranges.
const IPV4_DOCUMENTATION_RANGES: Array<[number, number, number]> = [
  [192, 0, 2], // 192.0.2.0/24 (TEST-NET-1)
  [198, 51, 100], // 198.51.100.0/24 (TEST-NET-2)
  [203, 0, 113], // 203.0.113.0/24 (TEST-NET-3)
];

function classifyIpv4(ip: string): IpCategory {
  const parts = ip.split('.').map(Number);
  const [a, b, c] = parts;

  if (a === 127) return 'LOOPBACK';
  if (a === 169 && b === 254) return 'LINK_LOCAL';
  if (a >= 224 && a <= 239) return 'MULTICAST'; // 224.0.0.0/4
  if (a === 255 && b === 255 && c === 255 && parts[3] === 255) return 'RESERVED'; // limited broadcast
  if (IPV4_DOCUMENTATION_RANGES.some(([ra, rb, rc]) => a === ra && b === rb && c === rc)) return 'DOCUMENTATION';
  if (a === 0) return 'RESERVED'; // 0.0.0.0/8 "this network"
  if (a >= 240) return 'RESERVED'; // 240.0.0.0/4 reserved for future use
  if (isPrivateIp(ip)) return 'PRIVATE'; // 10/8, 172.16/12, 192.168/16
  return 'PUBLIC';
}

function classifyIpv6(ip: string): IpCategory {
  const lower = ip.toLowerCase();
  if (lower === '::1') return 'LOOPBACK';
  if (lower === '::') return 'RESERVED'; // unspecified address
  if (lower.startsWith('ff')) return 'MULTICAST'; // ff00::/8
  if (lower.startsWith('fe80:') || lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) {
    return 'LINK_LOCAL'; // fe80::/10
  }
  if (lower.startsWith('fc') || lower.startsWith('fd')) return 'PRIVATE'; // fc00::/7 ULA
  if (lower.startsWith('2001:db8:')) return 'DOCUMENTATION'; // 2001:db8::/32
  // IPv4-mapped IPv6 (::ffff:a.b.c.d) — classify by the embedded IPv4 address.
  if (lower.startsWith('::ffff:') && lower.includes('.')) {
    return classifyIpv4(lower.substring(7));
  }
  return 'PUBLIC';
}

/**
 * Deterministic IP classification, shared by services/worker (gates which
 * IPs may be sent to an external GeoIP/reputation provider) and
 * services/api (labels IPs in forensic API responses) — one implementation
 * so the two services can never disagree about what counts as public.
 */
export function classifyIp(ip: string): IpClassification {
  if (net.isIPv4(ip)) {
    const category = classifyIpv4(ip);
    return { ip, version: 'v4', category, isRoutablePublic: category === 'PUBLIC' };
  }
  if (net.isIPv6(ip)) {
    const category = classifyIpv6(ip);
    return { ip, version: 'v6', category, isRoutablePublic: category === 'PUBLIC' };
  }
  return { ip, version: null, category: 'INVALID', isRoutablePublic: false };
}

const safeLookup = (
  hostname: string,
  options: dns.LookupOptions,
  callback: (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[] | any, family?: number) => void
) => {
  // Use dns.lookup with all option to get all addresses
  dns.lookup(hostname, { all: true }, (err, addresses) => {
    if (err) {
      return callback(err, '', 4);
    }
    
    if (!addresses || addresses.length === 0) {
      return callback(new Error(`DNS resolution failed for ${hostname}`), '', 4);
    }

    // Every address must be safe
    for (const record of addresses) {
      if (isPrivateIp(record.address)) {
        const error = new Error('SSRF attempt blocked: Resolved to an internal IP address');
        (error as NodeJS.ErrnoException).code = 'ECONNREFUSED';
        return callback(error, '', 4);
      }
    }

    // Ensure we match the expected callback signature
    if (options && options.all) {
      callback(null, addresses, 4);
    } else {
      callback(null, addresses[0].address, addresses[0].family);
    }
  });
};

export class HttpClient {
  private axiosInstance: AxiosInstance;
  private breaker: CircuitBreaker<[AxiosRequestConfig], any>;

  constructor(private name: string, options: HttpClientOptions = {}) {
    // Construct agents with safeLookup to mitigate SSRF and DNS rebinding
    const httpAgent = new http.Agent({ lookup: safeLookup });
    const httpsAgent = new https.Agent({ lookup: safeLookup });

    this.axiosInstance = axios.create({
      baseURL: options.baseURL,
      timeout: options.timeout || 10000, // 10s default timeout
      httpAgent,
      httpsAgent,
      maxRedirects: 5, // Bound redirects
      beforeRedirect: (redirectOptions: Record<string, any>) => {
        // Construct the URL to validate the redirect target
        const protocol = redirectOptions.protocol || 'http:';
        const hostname = redirectOptions.hostname || redirectOptions.host || '';
        const port = redirectOptions.port ? `:${redirectOptions.port}` : '';
        const path = redirectOptions.path || '/';
        const href = `${protocol}//${hostname}${port}${path}`;
        
        HttpClient.validateUrl(href);
      },
      proxy: false // Explicitly disable proxy overrides by default for safety
    });

    const breakerOptions = {
      timeout: options.circuitBreakerOptions?.timeout || 15000,
      errorThresholdPercentage: options.circuitBreakerOptions?.errorThresholdPercentage || 50,
      resetTimeout: options.circuitBreakerOptions?.resetTimeout || 30000,
      ...options.circuitBreakerOptions,
    };

    this.breaker = new CircuitBreaker(
      (config: AxiosRequestConfig) => this.axiosInstance.request(config),
      breakerOptions
    );

    this.breaker.on('open', () => {
      console.warn(`Circuit breaker for ${this.name} is OPEN`);
    });

    this.breaker.on('halfOpen', () => {
      console.info(`Circuit breaker for ${this.name} is HALF-OPEN`);
    });

    this.breaker.on('close', () => {
      console.info(`Circuit breaker for ${this.name} is CLOSED`);
    });
  }

  public static validateUrl(url: string, baseURL?: string) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url, baseURL || 'http://localhost');
    } catch (e) {
      throw new Error('SSRF attempt blocked: Invalid URL format');
    }
    
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      throw new Error('SSRF attempt blocked: Unsupported protocol');
    }
    if (parsedUrl.username || parsedUrl.password) {
      throw new Error('SSRF attempt blocked: Embedded credentials in URL are not allowed');
    }

    // Node's lookup is skipped if hostname is an IP address
    const hostname = parsedUrl.hostname;
    // Handle IPv6 bracket notation e.g. [::1]
    const ip = hostname.startsWith('[') && hostname.endsWith(']') 
        ? hostname.slice(1, -1) 
        : hostname;
        
    if (net.isIP(ip) && isPrivateIp(ip)) {
      throw new Error('SSRF attempt blocked: Resolved to an internal IP address');
    }
  }

  public async request<T = any>(config: AxiosRequestConfig): Promise<T> {
    // Strip any security-critical overrides from request config
    const safeConfig: AxiosRequestConfig = { ...config };
    delete safeConfig.httpAgent;
    delete safeConfig.httpsAgent;
    delete safeConfig.lookup;
    delete safeConfig.transport;
    delete safeConfig.socketPath;
    delete safeConfig.proxy;
    delete safeConfig.beforeRedirect;
    delete safeConfig.maxRedirects;

    if (safeConfig.url) {
      HttpClient.validateUrl(safeConfig.url, safeConfig.baseURL || this.axiosInstance.defaults.baseURL);
    }
    try {
      const response = await this.breaker.fire(safeConfig);
      return response.data;
    } catch (error) {
      throw error;
    }
  }

  public async get<T = any>(url: string, config?: Omit<AxiosRequestConfig, 'url' | 'method'>): Promise<T> {
    return this.request<T>({ ...config, url, method: 'GET' });
  }

  public async post<T = any>(url: string, data?: any, config?: Omit<AxiosRequestConfig, 'url' | 'method' | 'data'>): Promise<T> {
    return this.request<T>({ ...config, url, method: 'POST', data });
  }
}
