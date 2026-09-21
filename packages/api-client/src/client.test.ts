import { describe, it, expect, vi } from 'vitest';
import { CiperscopeApiClient, ApiError } from './client';

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  } as unknown as Response;
}

function makeClient(fetchImpl: typeof fetch, onUnauthorized?: () => void) {
  return new CiperscopeApiClient({
    baseUrl: 'https://api.test/v1',
    getOrganizationId: () => 'org-1',
    onUnauthorized,
    fetchImpl,
  });
}

describe('CiperscopeApiClient — request plumbing', () => {
  it('sends the organization id header and credentials on every request', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ id: 'e1', analysisStatus: 'COMPLETED', classification: null, riskScore: null, createdAt: '2026-01-01', riskAssessment: null }));
    const client = makeClient(fetchMock as unknown as typeof fetch);

    await client.getEmailAnalysis('e1');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.test/v1/emails/e1/analysis');
    expect(init.credentials).toBe('include');
    expect((init.headers as Headers).get('x-organization-id')).toBe('org-1');
  });

  it('calls onUnauthorized and throws ApiError on a 401', async () => {
    const onUnauthorized = vi.fn();
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ message: 'Invalid or missing token' }, 401));
    const client = makeClient(fetchMock as unknown as typeof fetch, onUnauthorized);

    await expect(client.getEmailAnalysis('e1')).rejects.toBeInstanceOf(ApiError);
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it('surfaces the backend error message on a non-2xx response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ message: 'Email not found' }, 404));
    const client = makeClient(fetchMock as unknown as typeof fetch);

    await expect(client.getEmailAnalysis('missing')).rejects.toThrow('Email not found');
  });

  it('falls back to a generic message when the error body is malformed JSON', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: () => Promise.reject(new Error('not json')),
    } as unknown as Response);
    const client = makeClient(fetchMock as unknown as typeof fetch);

    await expect(client.getEmailAnalysis('e1')).rejects.toThrow('API error: 500');
  });
});

describe('CiperscopeApiClient — DKIM honesty mapping', () => {
  it('derives cryptographicallyVerified: true only when the backend result is PASS', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        dkimVerifications: [
          { result: 'PASS', domain: 'example.com', selector: 's1', explanation: 'Signature cryptographically verified using key at s1._domainkey.example.com' },
        ],
      })
    );
    const client = makeClient(fetchMock as unknown as typeof fetch);

    const { dkimVerifications } = await client.getEmailDkim('e1');

    expect(dkimVerifications).toHaveLength(1);
    expect(dkimVerifications[0].result).toBe('PASS');
    expect(dkimVerifications[0].cryptographicallyVerified).toBe(true);
  });

  it.each(['FAIL', 'PERMERROR', 'TEMPERROR', 'NONE', 'NEUTRAL', 'SOFTFAIL'] as const)(
    'derives cryptographicallyVerified: false for a non-PASS backend result (%s) — presence/syntax is never enough',
    async (result) => {
      const fetchMock = vi.fn().mockResolvedValue(
        jsonResponse({
          dkimVerifications: [{ result, domain: 'example.com', selector: 's1', explanation: 'not a real pass' }],
        })
      );
      const client = makeClient(fetchMock as unknown as typeof fetch);

      const { dkimVerifications } = await client.getEmailDkim('e1');

      expect(dkimVerifications[0].cryptographicallyVerified).toBe(false);
    }
  );

  it('handles an empty DKIM list without throwing', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ dkimVerifications: [] }));
    const client = makeClient(fetchMock as unknown as typeof fetch);

    const { dkimVerifications } = await client.getEmailDkim('e1');
    expect(dkimVerifications).toEqual([]);
  });
});

describe('CiperscopeApiClient — analyst decisions mapping', () => {
  it('maps raw AuditLog rows (metadata-nested fields) into the AnalystDecision contract', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        decisions: [
          {
            id: 'audit-1',
            actorId: 'user-1',
            createdAt: '2026-01-02T00:00:00.000Z',
            metadata: { caseId: 'case-1', targetId: 'ind-1', targetType: 'Indicator', decision: 'CONFIRMED', reason: 'Matches known campaign' },
          },
        ],
      })
    );
    const client = makeClient(fetchMock as unknown as typeof fetch);

    const { items } = await client.getInvestigationDecisions('case-1', 'inv-1');

    expect(items).toEqual([
      {
        id: 'audit-1',
        targetId: 'ind-1',
        targetType: 'Indicator',
        decision: 'CONFIRMED',
        reason: 'Matches known campaign',
        actorId: 'user-1',
        createdAt: '2026-01-02T00:00:00.000Z',
      },
    ]);
  });

  it('does not throw when metadata is missing, and falls back to safe defaults', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({ decisions: [{ id: 'audit-2', actorId: null, createdAt: '2026-01-02T00:00:00.000Z' }] })
    );
    const client = makeClient(fetchMock as unknown as typeof fetch);

    const { items } = await client.getInvestigationDecisions('case-1', 'inv-1');
    expect(items[0].targetId).toBe('');
    expect(items[0].targetType).toBe('');
    expect(items[0].decision).toBe('REVIEWED');
  });

  it('returns an empty list when there are no decisions yet', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ decisions: [] }));
    const client = makeClient(fetchMock as unknown as typeof fetch);

    const { items } = await client.getInvestigationDecisions('case-1', 'inv-1');
    expect(items).toEqual([]);
  });
});
