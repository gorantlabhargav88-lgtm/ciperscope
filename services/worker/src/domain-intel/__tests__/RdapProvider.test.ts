import { describe, it, expect, vi } from 'vitest';
import { RdapProvider } from '../RdapProvider';
import { RdapClient, RdapFetchResult } from '../RdapClient';

function fakeClient(result: RdapFetchResult): RdapClient {
  return { fetchDomain: vi.fn().mockResolvedValue(result) } as unknown as RdapClient;
}

describe('RdapProvider', () => {
  it('parses a real-shaped RDAP domain response into registrar/dates/nameservers/status', async () => {
    const provider = new RdapProvider(fakeClient({
      outcome: 'SUCCESS',
      rdapSource: 'https://rdap.example-registry.net/',
      response: {
        ldhName: 'evil-example.com',
        status: ['active', 'clientTransferProhibited'],
        nameservers: [{ ldhName: 'ns1.evil-example.com' }, { ldhName: 'ns2.evil-example.com' }],
        entities: [
          { roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Evil Registrar LLC']]] },
          { roles: ['administrative'], vcardArray: ['vcard', [['fn', {}, 'text', 'Should Not Be Used']]] },
        ],
        events: [
          { eventAction: 'registration', eventDate: '2020-01-01T00:00:00Z' },
          { eventAction: 'expiration', eventDate: '2030-01-01T00:00:00Z' },
          { eventAction: 'last changed', eventDate: '2025-01-01T00:00:00Z' },
        ],
      },
    }));

    const outcome = await provider.lookup('evil-example.com');
    expect(outcome.status).toBe('SUCCESS');
    expect(outcome.data).toEqual({
      registrar: 'Evil Registrar LLC',
      registrationDate: new Date('2020-01-01T00:00:00Z'),
      expirationDate: new Date('2030-01-01T00:00:00Z'),
      nameservers: ['ns1.evil-example.com', 'ns2.evil-example.com'],
      domainStatus: ['active', 'clientTransferProhibited'],
      rdapSource: 'https://rdap.example-registry.net/',
    });
  });

  it('never fabricates a field the RDAP response did not actually include', async () => {
    const provider = new RdapProvider(fakeClient({
      outcome: 'SUCCESS',
      rdapSource: 'https://rdap.example-registry.net/',
      response: { ldhName: 'sparse-example.com' }, // no entities/events/nameservers/status at all
    }));

    const outcome = await provider.lookup('sparse-example.com');
    expect(outcome.status).toBe('SUCCESS');
    expect(outcome.data).toEqual({
      registrar: null,
      registrationDate: null,
      expirationDate: null,
      nameservers: [],
      domainStatus: [],
      rdapSource: 'https://rdap.example-registry.net/',
    });
  });

  it('maps NOT_FOUND / PROVIDER_TIMEOUT / PROVIDER_ERROR honestly, with null data', async () => {
    expect((await new RdapProvider(fakeClient({ outcome: 'NOT_FOUND' })).lookup('x.com'))).toEqual({ status: 'NOT_FOUND', data: null });
    expect((await new RdapProvider(fakeClient({ outcome: 'PROVIDER_TIMEOUT' })).lookup('x.com'))).toEqual({ status: 'PROVIDER_TIMEOUT', data: null });
    const errResult = await new RdapProvider(fakeClient({ outcome: 'PROVIDER_ERROR', errorMessage: 'boom' })).lookup('x.com');
    expect(errResult).toEqual({ status: 'PROVIDER_ERROR', data: null, errorMessage: 'boom' });
  });
});
