import { IndicatorType } from '@ciperscope/database';

export interface NormalizedIoc {
  type: IndicatorType;
  value: string;
}

export class IocNormalizer {
  /**
   * Normalizes an IP address. Returns null if invalid.
   */
  public static normalizeIp(ip: string): NormalizedIoc | null {
    if (!ip) return null;
    const trimmed = ip.trim();

    // Validate IPv4 correctly (0-255)
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$/;

    if (ipv4Regex.test(trimmed) || ipv6Regex.test(trimmed)) {
      return { type: IndicatorType.IP, value: trimmed };
    }

    return null;
  }

  /**
   * Normalizes a domain name. Returns null if invalid.
   */
  public static normalizeDomain(domain: string): NormalizedIoc | null {
    if (!domain) return null;
    const trimmed = domain.trim().toLowerCase();

    const domainRegex = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/;
    if (domainRegex.test(trimmed)) {
      return { type: IndicatorType.DOMAIN, value: trimmed };
    }

    return null;
  }

  /**
   * Extracts the base hostname from a URL to prevent PII leakage and SSRF.
   * Treats the result as a DOMAIN indicator.
   */
  public static normalizeUrl(url: string): NormalizedIoc | null {
    if (!url) return null;
    try {
      const parsed = new URL(url.trim());
      // We only extract the hostname. This inherently drops paths, query params, etc.
      return IocNormalizer.normalizeDomain(parsed.hostname);
    } catch {
      return null;
    }
  }

  /**
   * Normalizes a cryptographic hash (SHA256). Returns null if invalid.
   */
  public static normalizeHash(hash: string): NormalizedIoc | null {
    if (!hash) return null;
    const trimmed = hash.trim().toLowerCase();

    if (/^[a-f0-9]{64}$/.test(trimmed)) {
      return { type: IndicatorType.HASH, value: trimmed };
    }

    return null;
  }
}
