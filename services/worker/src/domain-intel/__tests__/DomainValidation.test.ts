import { describe, it, expect } from 'vitest';
import { validateAndReduceDomain } from '../DomainValidation';

describe('validateAndReduceDomain', () => {
  it('reduces a hostname to its registrable domain', () => {
    const result = validateAndReduceDomain('mail.sub.example.com');
    expect(result).toEqual({ ok: true, registrableDomain: 'example.com' });
  });

  it('accepts an already-registrable domain unchanged', () => {
    expect(validateAndReduceDomain('example.com')).toEqual({ ok: true, registrableDomain: 'example.com' });
  });

  it('handles a multi-part public suffix (e.g. co.uk)', () => {
    expect(validateAndReduceDomain('www.example.co.uk')).toEqual({ ok: true, registrableDomain: 'example.co.uk' });
  });

  it('rejects a malformed domain (no dot, empty label, too long)', () => {
    expect(validateAndReduceDomain('notadomain')).toEqual({ ok: false, reason: 'MALFORMED_DOMAIN' });
    expect(validateAndReduceDomain('foo..com')).toEqual({ ok: false, reason: 'MALFORMED_DOMAIN' });
    expect(validateAndReduceDomain('')).toEqual({ ok: false, reason: 'MALFORMED_DOMAIN' });
    expect(validateAndReduceDomain('a'.repeat(260))).toEqual({ ok: false, reason: 'MALFORMED_DOMAIN' });
  });

  it('rejects a private/internal/reserved domain without ever attempting RDAP', () => {
    expect(validateAndReduceDomain('server.local')).toEqual({ ok: false, reason: 'PRIVATE_OR_RESERVED' });
    expect(validateAndReduceDomain('intranet.internal')).toEqual({ ok: false, reason: 'PRIVATE_OR_RESERVED' });
    expect(validateAndReduceDomain('example.test')).toEqual({ ok: false, reason: 'PRIVATE_OR_RESERVED' });
    expect(validateAndReduceDomain('foo.invalid')).toEqual({ ok: false, reason: 'PRIVATE_OR_RESERVED' });
  });

  it('rejects an IP literal presented as a "domain"', () => {
    expect(validateAndReduceDomain('203.0.113.5')).toEqual({ ok: false, reason: 'PRIVATE_OR_RESERVED' });
    expect(validateAndReduceDomain('::1')).toEqual({ ok: false, reason: 'PRIVATE_OR_RESERVED' });
  });

  it('is case-insensitive', () => {
    expect(validateAndReduceDomain('MAIL.EXAMPLE.COM')).toEqual({ ok: true, registrableDomain: 'example.com' });
  });
});
