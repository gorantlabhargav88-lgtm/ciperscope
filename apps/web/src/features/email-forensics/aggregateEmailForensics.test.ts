import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiError } from '@ciperscope/api-client';
import type { EmailAnalysisSummary } from '@ciperscope/types';

const mockClient = {
  getEmailAnalysis: vi.fn(),
  getEmailHeaders: vi.fn(),
  getEmailReceivedHops: vi.fn(),
  getEmailMimeParts: vi.fn(),
  getEmailAuthenticationSummary: vi.fn(),
  getEmailSpf: vi.fn(),
  getEmailDkim: vi.fn(),
  getEmailDmarc: vi.fn(),
  getEmailUrls: vi.fn(),
  getEmailAttachments: vi.fn(),
  getEmailAiAnalysis: vi.fn(),
  getEmailThreatIndicators: vi.fn(),
  getEmailGeolocation: vi.fn(),
  getEmailEvidenceGraph: vi.fn(),
  getCase: vi.fn(),
  getCaseEvidenceList: vi.fn(),
  getCaseInvestigations: vi.fn(),
};

vi.mock('../../lib/apiClient', () => ({
  apiClient: mockClient,
}));

// Imported after the mock so it picks up the mocked module.
const { aggregateEmailForensics } = await import('./aggregateEmailForensics');

function baseEmail(overrides: Partial<EmailAnalysisSummary> = {}): EmailAnalysisSummary {
  return {
    id: 'email-1',
    caseId: null,
    analysisStatus: 'COMPLETED',
    classification: 'UNKNOWN',
    riskScore: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    riskAssessment: null,
    ...overrides,
  };
}

function setupDefaults() {
  mockClient.getEmailAnalysis.mockResolvedValue(baseEmail());
  mockClient.getEmailHeaders.mockResolvedValue({ headers: [] });
  mockClient.getEmailReceivedHops.mockResolvedValue({ hops: [] });
  mockClient.getEmailMimeParts.mockResolvedValue({ mimeParts: [] });
  mockClient.getEmailAuthenticationSummary.mockResolvedValue({ analysis: null });
  mockClient.getEmailSpf.mockResolvedValue({ spfVerifications: [] });
  mockClient.getEmailDkim.mockResolvedValue({ dkimVerifications: [] });
  mockClient.getEmailDmarc.mockResolvedValue({ dmarcVerification: null });
  mockClient.getEmailUrls.mockResolvedValue({ urls: [] });
  mockClient.getEmailAttachments.mockResolvedValue({ attachments: [] });
  mockClient.getEmailAiAnalysis.mockResolvedValue({ status: 'NOT_AVAILABLE', prediction: { status: 'NOT_AVAILABLE' } });
  mockClient.getEmailThreatIndicators.mockResolvedValue({ threatIndicators: [] });
  mockClient.getEmailGeolocation.mockResolvedValue({ geolocation: [] });
  mockClient.getEmailEvidenceGraph.mockResolvedValue({
    emailId: 'email-1',
    nodes: [],
    edges: [],
    metadata: { generatedAt: '2026-01-01T00:00:00.000Z', nodeCount: 0, edgeCount: 0, truncated: false },
  });
  mockClient.getCase.mockResolvedValue(null);
  mockClient.getCaseEvidenceList.mockResolvedValue({ items: [], nextCursor: null });
  mockClient.getCaseInvestigations.mockResolvedValue({ items: [] });
}

beforeEach(() => {
  vi.clearAllMocks();
  setupDefaults();
});

describe('aggregateEmailForensics', () => {
  it('uses the email analysis caseId to decide whether to fetch case-scoped data', async () => {
    mockClient.getEmailAnalysis.mockResolvedValue(baseEmail({ caseId: 'case-1' }));
    mockClient.getCase.mockResolvedValue({ id: 'case-1', organizationId: 'org-1', title: 'Case One', description: null, status: 'OPEN', priority: 'HIGH', assignedUserId: null, creatorId: 'u1', createdAt: '2026-01-01', updatedAt: '2026-01-01', resolvedAt: null });

    const result = await aggregateEmailForensics('email-1');

    expect(mockClient.getCase).toHaveBeenCalledWith('case-1');
    expect(result.investigationContext?.case?.title).toBe('Case One');
  });

  it('missing case (caseId null): evidence and investigationContext are honestly null, no case calls made', async () => {
    const result = await aggregateEmailForensics('email-1');

    expect(mockClient.getCase).not.toHaveBeenCalled();
    expect(result.evidence).toBeNull();
    expect(result.investigationContext).toBeNull();
  });

  it('missing investigation: an empty investigations list is represented as [], not fabricated', async () => {
    mockClient.getEmailAnalysis.mockResolvedValue(baseEmail({ caseId: 'case-1' }));
    mockClient.getCaseInvestigations.mockResolvedValue({ items: [] });

    const result = await aggregateEmailForensics('email-1');

    expect(result.investigationContext?.investigations).toEqual([]);
  });

  it('empty evidence: evidence resolves to an empty array, not null, when a case exists', async () => {
    mockClient.getEmailAnalysis.mockResolvedValue(baseEmail({ caseId: 'case-1' }));
    mockClient.getCaseEvidenceList.mockResolvedValue({ items: [], nextCursor: null });

    const result = await aggregateEmailForensics('email-1');

    expect(result.evidence).toEqual([]);
  });

  it('missing CTI: no threat indicators yields an empty cti array and zero malicious count, priority stays P3', async () => {
    mockClient.getEmailThreatIndicators.mockResolvedValue({ threatIndicators: [] });

    const result = await aggregateEmailForensics('email-1');

    expect(result.cti).toEqual([]);
    expect(result.threat.maliciousIndicatorCount).toBe(0);
    expect(result.threat.priority.priority).toBe('P3');
  });

  it('a malicious indicator plus CRITICAL severity escalates to P1, and CTI reflects the same data', async () => {
    mockClient.getEmailAnalysis.mockResolvedValue(
      baseEmail({ riskAssessment: { overallScore: 85, riskLevel: 'CRITICAL', version: 'v1', factors: [] } })
    );
    mockClient.getEmailThreatIndicators.mockResolvedValue({
      threatIndicators: [{ id: 'i1', iocType: 'IP', iocValue: '1.2.3.4', provider: 'AbuseIPDB', status: 'MALICIOUS', confidence: 90 }],
    });

    const result = await aggregateEmailForensics('email-1');

    expect(result.threat.priority.priority).toBe('P1');
    expect(result.cti).toHaveLength(1);
    expect(result.cti[0].verdict).toBe('MALICIOUS');
  });

  it('malformed/missing optional ML prediction data does not throw and yields an honest null classification', async () => {
    mockClient.getEmailAiAnalysis.mockResolvedValue({ prediction: {} });

    await expect(aggregateEmailForensics('email-1')).resolves.toMatchObject({
      threat: { mlClassification: null },
    });
  });

  it('computes dkimFailed from any FAILed DKIM signature, separately from authenticationFailed (Phase 8C)', async () => {
    mockClient.getEmailDkim.mockResolvedValue({
      dkimVerifications: [{ result: 'FAIL', domain: 'example.com', selector: 's1', explanation: null, cryptographicallyVerified: false }],
    });
    mockClient.getEmailSpf.mockResolvedValue({ spfVerifications: [{ result: 'PASS', domain: 'example.com', evaluatedIp: '1.2.3.4', matchedMechanism: null, explanation: null }] });
    mockClient.getEmailDmarc.mockResolvedValue({ dmarcVerification: { result: 'PASS', orgDomain: 'example.com', policy: 'reject', subdomainPolicy: null, spfAlignment: 'aligned', dkimAlignment: 'unaligned', explanation: null } });

    const result = await aggregateEmailForensics('email-1');

    expect(result.threat.dkimFailed).toBe(true);
    expect(result.threat.authenticationFailed).toBe(false);
  });

  it('does not let dkimFailed change the priority calculation, even when true alongside CRITICAL severity (no duplicate scoring contribution)', async () => {
    mockClient.getEmailAnalysis.mockResolvedValue(
      baseEmail({ riskAssessment: { overallScore: 30, riskLevel: 'CRITICAL', version: '1.0', factors: [] } })
    );
    mockClient.getEmailDkim.mockResolvedValue({
      dkimVerifications: [{ result: 'FAIL', domain: 'example.com', selector: 's1', explanation: null, cryptographicallyVerified: false }],
    });

    const withDkimFail = await aggregateEmailForensics('email-1');

    mockClient.getEmailDkim.mockResolvedValue({ dkimVerifications: [] });
    const withoutDkimFail = await aggregateEmailForensics('email-1');

    expect(withDkimFail.threat.dkimFailed).toBe(true);
    expect(withoutDkimFail.threat.dkimFailed).toBe(false);
    // Same severity/score/no other signals -> same priority regardless of dkimFailed.
    expect(withDkimFail.threat.priority).toEqual(withoutDkimFail.threat.priority);
  });

  it('passes through the client-derived DKIM cryptographicallyVerified flag unchanged, whether true or false', async () => {
    mockClient.getEmailDkim.mockResolvedValue({
      dkimVerifications: [
        { result: 'PASS', domain: 'example.com', selector: 's1', explanation: null, cryptographicallyVerified: true },
        { result: 'FAIL', domain: 'example.org', selector: 's2', explanation: null, cryptographicallyVerified: false },
      ],
    });

    const result = await aggregateEmailForensics('email-1');

    expect(result.authentication.dkim[0].cryptographicallyVerified).toBe(true);
    expect(result.authentication.dkim[1].cryptographicallyVerified).toBe(false);
  });

  it('propagates an unauthorized (401) failure from any underlying call rather than swallowing it', async () => {
    mockClient.getEmailAnalysis.mockRejectedValue(new ApiError(401, 'Invalid or missing token'));

    await expect(aggregateEmailForensics('email-1')).rejects.toThrow('Invalid or missing token');
  });

  it('a caseIdOverride is honored even when the email itself has no caseId', async () => {
    mockClient.getCase.mockResolvedValue({ id: 'case-9', organizationId: 'org-1', title: 'Override Case', description: null, status: 'OPEN', priority: 'LOW', assignedUserId: null, creatorId: 'u1', createdAt: '2026-01-01', updatedAt: '2026-01-01', resolvedAt: null });

    const result = await aggregateEmailForensics('email-1', 'case-9');

    expect(mockClient.getCase).toHaveBeenCalledWith('case-9');
    expect(result.investigationContext?.case?.id).toBe('case-9');
  });
});
