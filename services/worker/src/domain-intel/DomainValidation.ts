import psl from 'psl';
import net from 'net';

// Special-use / reserved TLDs (RFC 2606, RFC 6761, RFC 7686) that will
// never have a real RDAP registration — rejected locally so we never waste
// an RDAP lookup (or a rate-limit slot) on them.
const RESERVED_TLDS = new Set(['local', 'localhost', 'internal', 'test', 'invalid', 'example', 'onion']);

export type DomainValidationResult =
  | { ok: true; registrableDomain: string }
  | { ok: false; reason: 'MALFORMED_DOMAIN' | 'PRIVATE_OR_RESERVED' };

/**
 * Reduces a hostname/domain to its registrable (public-suffix + 1) form
 * for RDAP lookup, or explains why it can never have one — never silently
 * passing through something RDAP would reject anyway.
 */
export function validateAndReduceDomain(input: string): DomainValidationResult {
  const domain = input.trim().toLowerCase();
  if (domain.length === 0 || domain.length > 253) return { ok: false, reason: 'MALFORMED_DOMAIN' };
  if (net.isIP(domain) !== 0) return { ok: false, reason: 'PRIVATE_OR_RESERVED' };

  const labels = domain.split('.');
  if (labels.length < 2 || labels.some((l) => l.length === 0)) return { ok: false, reason: 'MALFORMED_DOMAIN' };

  const tld = labels[labels.length - 1];
  if (RESERVED_TLDS.has(tld)) return { ok: false, reason: 'PRIVATE_OR_RESERVED' };

  const registrable = psl.get(domain);
  if (!registrable) return { ok: false, reason: 'MALFORMED_DOMAIN' };

  return { ok: true, registrableDomain: registrable };
}
