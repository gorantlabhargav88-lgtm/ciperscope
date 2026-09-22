import psl from 'psl';

/**
 * Deterministic, offline brand-impersonation detection for a URL hostname.
 * No network lookups (no DNS/WHOIS/domain-age) — pure string analysis, so it
 * never blocks on or depends on an external service.
 *
 * Distinguishes what CipherScope's UrlExtractor previously could not:
 * the *registrable domain* (via `psl`, the same library DmarcVerifier
 * already uses for alignment checks) vs. the full hostname, so
 * `amazon-login.example.com` (impersonation attempt, registrable domain
 * `example.com`) is not confused with a real `amazon.com` subdomain.
 */

// A small, representative set of frequently-impersonated brands. Extend as
// needed — this is intentionally not exhaustive, to keep false positives
// low and the list auditable.
export const KNOWN_BRANDS: readonly string[] = [
  'amazon', 'google', 'microsoft', 'apple', 'paypal', 'facebook', 'netflix',
  'chase', 'wellsfargo', 'bankofamerica', 'dropbox', 'linkedin', 'instagram',
];

// Visually-confusable characters mapped to the Latin letter they impersonate.
// Covers the common digit-for-letter substitutions (amaz0n, g00gle) and the
// Cyrillic homoglyphs most frequently used in phishing kits (а/е/о/р/с/х/у).
const CONFUSABLE_MAP: Record<string, string> = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't',
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'ѕ': 's', 'і': 'i',
};

function normalizeConfusables(label: string): string {
  return Array.from(label.toLowerCase())
    .map((ch) => CONFUSABLE_MAP[ch] ?? ch)
    .join('');
}

function containsNonAscii(label: string): boolean {
  return Array.from(label).some((ch) => ch.charCodeAt(0) > 127);
}

/** Standard Levenshtein edit distance (insert/delete/substitute), unbounded. */
function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[] = Array.from({ length: n + 1 }, (_, j) => j);

  for (let i = 1; i <= m; i++) {
    let prevDiag = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] = a[i - 1] === b[j - 1]
        ? prevDiag
        : 1 + Math.min(prevDiag, dp[j - 1], dp[j]);
      prevDiag = tmp;
    }
  }
  return dp[n];
}

export interface BrandImpersonationResult {
  indicators: string[];
  /** Human-readable evidence explaining each indicator, same order. */
  descriptions: string[];
}

/**
 * @param hostname the URL's hostname (e.g. `new URL(url).hostname`), NOT the
 * anchor/display text — callers must never substitute visible link text here.
 */
export function detectBrandImpersonation(hostname: string): BrandImpersonationResult {
  const indicators: string[] = [];
  const descriptions: string[] = [];
  if (!hostname) return { indicators, descriptions };

  const lowerHost = hostname.toLowerCase();
  const parsedRegistrable = psl.get(lowerHost);
  const registrableDomain = parsedRegistrable ?? lowerHost;
  const registrableSecondLevel = registrableDomain.split('.')[0];
  const normalizedSecondLevel = normalizeConfusables(registrableSecondLevel);

  for (const brand of KNOWN_BRANDS) {
    // Exact, legitimate match on the registrable domain — not impersonation.
    if (normalizedSecondLevel === brand && registrableSecondLevel === brand) {
      continue;
    }

    // Homoglyph: the registrable second-level label isn't the brand as
    // written, but normalizing confusable characters makes it identical.
    if (normalizedSecondLevel === brand && registrableSecondLevel !== brand) {
      indicators.push('BRAND_IMPERSONATION_HOMOGLYPH');
      descriptions.push(
        `Registrable domain "${registrableDomain}" uses characters that visually impersonate "${brand}" ` +
        `(normalizes to "${brand}" once confusable characters are resolved).`
      );
      continue;
    }

    // Typosquat: small edit distance from the brand name (1-2 edits), on
    // the normalized label, and not already flagged as a homoglyph match.
    const distance = editDistance(normalizedSecondLevel, brand);
    if (distance > 0 && distance <= 2 && normalizedSecondLevel.length >= brand.length - 2) {
      indicators.push('BRAND_IMPERSONATION_TYPOSQUAT');
      descriptions.push(
        `Registrable domain "${registrableDomain}" is a likely typosquat of "${brand}.com" ` +
        `(edit distance ${distance}).`
      );
      continue;
    }

    // Deceptive subdomain: the brand name appears as a distinct label
    // somewhere in the hostname, but the actual registrable domain is a
    // different, unrelated domain (e.g. amazon-login.example.com,
    // amazon.com.example.com).
    if (registrableSecondLevel !== brand) {
      const labels = lowerHost.split('.');
      const brandInSubdomain = labels.some((label) => {
        if (label === registrableSecondLevel) return false; // that's the registrable label itself, handled above
        const normalizedLabel = normalizeConfusables(label);
        return normalizedLabel === brand || normalizedLabel.includes(brand);
      });
      if (brandInSubdomain) {
        indicators.push('BRAND_IMPERSONATION_SUBDOMAIN');
        descriptions.push(
          `Hostname "${hostname}" references "${brand}" in a subdomain label, but the actual registrable ` +
          `domain is "${registrableDomain}", not a "${brand}"-owned domain.`
        );
      }
    }
  }

  if (containsNonAscii(hostname) && indicators.length === 0) {
    // Non-ASCII hostname that didn't match a known brand homoglyph pattern —
    // still worth surfacing as a general confusable-script indicator.
    indicators.push('NON_ASCII_HOSTNAME');
    descriptions.push(`Hostname "${hostname}" contains non-ASCII characters, which can be used for visual spoofing.`);
  }

  return { indicators, descriptions };
}
