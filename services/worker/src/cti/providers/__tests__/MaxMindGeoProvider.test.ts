import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }));

vi.mock('@ciperscope/http-client', async () => {
  const actual = await vi.importActual<typeof import('@ciperscope/http-client')>('@ciperscope/http-client');
  return {
    ...actual,
    HttpClient: vi.fn().mockImplementation(() => ({ get: mockGet })),
  };
});

vi.mock('@ciperscope/logger', () => ({ logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() } }));

import { MaxMindGeoProvider } from '../MaxMindGeoProvider';
import { logger } from '@ciperscope/logger';

describe('MaxMindGeoProvider', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('never calls the HTTP client for a private IP — refuses before any request', async () => {
    const provider = new MaxMindGeoProvider('account-id', 'license-key');
    const result = await provider.lookup('10.0.0.5');

    expect(result).toBeNull();
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('never calls the HTTP client for a loopback IP', async () => {
    const provider = new MaxMindGeoProvider('account-id', 'license-key');
    await provider.lookup('127.0.0.1');
    expect(mockGet).not.toHaveBeenCalled();
  });

  it('maps a successful response into the normalized GeoLocationResult shape', async () => {
    mockGet.mockResolvedValue({
      country: { iso_code: 'US', names: { en: 'United States' } },
      subdivisions: [{ names: { en: 'California' } }],
      city: { names: { en: 'Mountain View' } },
      location: { latitude: 37.386, longitude: -122.0838 },
      traits: { autonomous_system_number: 15169, autonomous_system_organization: 'GOOGLE', isp: 'Google LLC' },
    });

    const provider = new MaxMindGeoProvider('account-id', 'license-key');
    const result = await provider.lookup('8.8.8.8');

    expect(result).toEqual({
      providerName: 'MaxMind',
      country: 'United States',
      region: 'California',
      city: 'Mountain View',
      latitude: 37.386,
      longitude: -122.0838,
      asn: 'AS15169',
      isp: 'Google LLC',
    });
  });

  it('passes the account credentials as HTTP Basic Auth, not in the URL or headers', async () => {
    mockGet.mockResolvedValue({});
    const provider = new MaxMindGeoProvider('acct-123', 'license-abc');
    await provider.lookup('1.1.1.1');

    const [url, options] = mockGet.mock.calls[0];
    expect(url).not.toContain('acct-123');
    expect(url).not.toContain('license-abc');
    expect(options.auth).toEqual({ username: 'acct-123', password: 'license-abc' });
  });

  it('returns null (not a thrown error) on a 404 — "no data for this IP" is not a failure', async () => {
    mockGet.mockRejectedValue({ response: { status: 404 } });
    const provider = new MaxMindGeoProvider('account-id', 'license-key');
    const result = await provider.lookup('1.1.1.1');
    expect(result).toBeNull();
  });

  it('returns null (not a thrown error) on a network/timeout failure', async () => {
    mockGet.mockRejectedValue(new Error('timeout of 5000ms exceeded'));
    const provider = new MaxMindGeoProvider('account-id', 'license-key');
    const result = await provider.lookup('1.1.1.1');
    expect(result).toBeNull();
  });

  it('the license key never appears in a thrown/logged error message', async () => {
    const secretError = { response: { status: 500 }, config: { auth: { username: 'acct-123', password: 'super-secret-license-key' } }, message: 'Request failed with status code 500' };
    mockGet.mockRejectedValue(secretError);

    const provider = new MaxMindGeoProvider('acct-123', 'super-secret-license-key');
    await provider.lookup('1.1.1.1');

    const allLogCalls = JSON.stringify((logger.warn as ReturnType<typeof vi.fn>).mock.calls);
    expect(allLogCalls).not.toContain('super-secret-license-key');
  });
});
