import * as cheerio from 'cheerio';
import { detectBrandImpersonation } from './BrandImpersonationDetector';

export interface ExtractedUrl {
  originalObservedUrl: string;
  normalizedUrl: string | null;
  source: 'TEXT' | 'HTML_HREF' | 'HTML_SRC' | 'HTML_ACTION' | 'QR_CODE' | 'OTHER';
  isObfuscated: boolean;
  indicators: string[];
}

export class UrlExtractor {
  private static readonly MAX_URLS = 1000;
  private static readonly MAX_URL_LENGTH = 2048;

  public static extractFromText(text: string): ExtractedUrl[] {
    const urls: ExtractedUrl[] = [];
    // Basic regex to find http/https URLs in plain text
    const regex = /(https?:\/\/[^\s]+)/gi;
    let match;
    while ((match = regex.exec(text)) !== null && urls.length < this.MAX_URLS) {
      const observed = match[1];
      if (observed.length <= this.MAX_URL_LENGTH) {
        urls.push(this.analyzeSingleUrl(observed, 'TEXT'));
      }
    }
    return urls;
  }

  public static extractFromHtml(html: string): ExtractedUrl[] {
    const urls: ExtractedUrl[] = [];
    
    // Parse safely without executing JS
    const $ = cheerio.load(html, {
      xmlMode: false
    });

    const addUrl = (url: string, source: ExtractedUrl['source']) => {
      if (!url) return;
      if (urls.length >= this.MAX_URLS) return;
      if (url.length > this.MAX_URL_LENGTH) return;
      
      // Ignore relative URLs or let normalization handle them (we want absolute http/https mostly)
      if (url.startsWith('http://') || url.startsWith('https://')) {
        urls.push(this.analyzeSingleUrl(url, source));
      }
    };

    $('a[href]').each((_, el) => addUrl($(el).attr('href') || '', 'HTML_HREF'));
    $('img[src], script[src], iframe[src]').each((_, el) => addUrl($(el).attr('src') || '', 'HTML_SRC'));
    $('form[action]').each((_, el) => addUrl($(el).attr('action') || '', 'HTML_ACTION'));

    return urls;
  }

  /**
   * Analyzes a single URL string using the exact same logic
   * extractFromText/extractFromHtml use internally (IP-literal/obfuscation/
   * brand-impersonation/homoglyph/typosquat detection, normalization) — the
   * single public entry point for any caller with one URL already in hand
   * (e.g. a QR-decoded payload) rather than a whole document to scan.
   */
  public static analyzeSingleUrl(observed: string, source: ExtractedUrl['source']): ExtractedUrl {
    const indicators: string[] = [];
    let isObfuscated = false;
    let normalized: string | null = null;

    // Detect basic obfuscation indicators
    if (/%[0-9a-f]{2}/i.test(observed)) {
      indicators.push('PERCENT_ENCODING');
      isObfuscated = true;
    }
    if (/&#[0-9]+;|&\w+;/i.test(observed)) {
      indicators.push('HTML_ENTITY_ENCODING');
      isObfuscated = true;
    }

    try {
      const parsedUrl = new URL(observed);
      
      // Enforce scheme whitelist
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        indicators.push('DANGEROUS_SCHEME');
        return { originalObservedUrl: observed, normalizedUrl: null, source, isObfuscated, indicators };
      }

      if (parsedUrl.username || parsedUrl.password) {
        indicators.push('EMBEDDED_CREDENTIALS');
        isObfuscated = true;
      }

      if (parsedUrl.port && parsedUrl.port !== '80' && parsedUrl.port !== '443') {
        indicators.push('UNUSUAL_PORT');
      }

      // Detect IP literals (basic IPv4)
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parsedUrl.hostname)) {
        indicators.push('IP_LITERAL');
        if (parsedUrl.hostname.startsWith('10.') || parsedUrl.hostname.startsWith('192.168.') || parsedUrl.hostname.match(/^172\.(1[6-9]|2\d|3[0-1])\./)) {
           indicators.push('PRIVATE_IP_LITERAL');
        }
      }

      if (parsedUrl.hostname === 'localhost' || parsedUrl.hostname === '127.0.0.1') {
        indicators.push('LOCALHOST');
      }

      // Check for Hex/Decimal/Octal IPv4 (URL class often normalizes this, we check the observed host vs normalized)
      const hostRegexMatch = observed.match(/https?:\/\/([^/]+)/);
      if (hostRegexMatch) {
         const rawHost = hostRegexMatch[1].split(':')[0]; // exclude port
         if (/0[xX][0-9a-fA-F]+/.test(rawHost) || /^\d+$/.test(rawHost)) {
           indicators.push('OBFUSCATED_IP_LITERAL');
           isObfuscated = true;
         }
      }

      const domainParts = parsedUrl.hostname.split('.');
      if (domainParts.length > 4) {
        indicators.push('EXCESSIVE_SUBDOMAINS');
      }

      if (parsedUrl.hostname.includes('xn--')) {
        indicators.push('PUNYCODE');
        isObfuscated = true;
      }

      // Brand impersonation: evaluated against the actual destination
      // hostname only, never against link/anchor display text (the caller
      // has no display text at this layer, so this is inherently safe).
      const brandCheck = detectBrandImpersonation(parsedUrl.hostname);
      if (brandCheck.indicators.length > 0) {
        indicators.push(...brandCheck.indicators);
        isObfuscated = true;
      }

      normalized = parsedUrl.toString();

    } catch (e) {
      indicators.push('MALFORMED_URL');
      isObfuscated = true;
    }

    return {
      originalObservedUrl: observed,
      normalizedUrl: normalized,
      source,
      isObfuscated,
      indicators
    };
  }
}
