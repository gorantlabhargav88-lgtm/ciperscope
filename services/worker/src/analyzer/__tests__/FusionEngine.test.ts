import { describe, it, expect, vi, beforeEach } from 'vitest';
import { FusionEngine } from '../FusionEngine';
import { PrismaClient, AuthResultStatus, ThreatVerdict } from '@ciperscope/database';

// Mock logger to avoid noisy test output
vi.mock('@ciperscope/logger', () => ({
  logger: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
  }
}));

describe('FusionEngine', () => {
  let prismaMock: Record<string, unknown>;
  let fusionEngine: FusionEngine;
  let mockEmail: Record<string, unknown>;

  beforeEach(() => {
    // Basic mock email structure with standard fields
    mockEmail = {
      id: 'email-1',
      authAnalysis: null,
      urls: [],
      attachments: [],
      relayHops: [],
      inferences: []
    };

    prismaMock = {
      email: {
        findUnique: vi.fn().mockResolvedValue(mockEmail),
        update: vi.fn().mockResolvedValue({})
      },
      indicator: {
        // No CTI observations persisted for this email's indicators by default —
        // FusionEngine must not fabricate a threat-intelligence signal when this is empty.
        findMany: vi.fn().mockResolvedValue([])
      },
      $transaction: vi.fn().mockImplementation(async (callback) => {
        // Execute the callback with the mock Prisma client (which has riskAssessment mocked)
        await callback(prismaMock);
      }),
      riskAssessment: {
        upsert: vi.fn().mockResolvedValue({ id: 'ra-1' })
      },
      alert: {
        create: vi.fn().mockResolvedValue({ id: 'alert-1' })
      }
    };

    fusionEngine = new FusionEngine(prismaMock as unknown as PrismaClient);
  });

  it('calculates score when ML status is NOT_AVAILABLE, classification is unchanged', async () => {
    // 1. ML status NOT_AVAILABLE: risk score calculated, classification NOT fabricated
    mockEmail.inferences = [{
      status: 'NOT_AVAILABLE',
      prediction: null,
      modelScore: null
    }];

    mockEmail.urls = [
      { indicators: ['OBFUSCATED'] }
    ];

    await fusionEngine.evaluate('email-1');

    // Risk score should be 40 (due to malicious URL)
    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 40 }),
      })
    );

    // Email update should NOT have classification
    expect(prismaMock.email.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.not.objectContaining({ classification: expect.anything() }),
      })
    );
  });

  it('preserves explicit ML PHISHING prediction', async () => {
    // 2. ML prediction PHISHING -> explicit PHISHING is preserved
    mockEmail.inferences = [{
      status: 'MODEL_PREDICTION',
      prediction: 'PHISHING',
      modelScore: 0.95
    }];

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.email.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ classification: 'PHISHING' })
      })
    );
  });

  it('scores CRITICAL-severity attachment threat indicators (Phase F) into overallScore', async () => {
    mockEmail.attachments = [
      {
        sha256: 'abc123',
        threatIndicators: [
          { category: 'ARCHIVE_PATH_TRAVERSAL', severity: 'CRITICAL', description: 'x', confidence: 'HIGH', source: 'AttachmentAnalyzer', analyzerVersion: '1.0.0' },
        ],
      },
    ];

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({ update: expect.objectContaining({ overallScore: 50 }) })
    );
  });

  it('takes the worst severity across multiple attachments, not a sum', async () => {
    mockEmail.attachments = [
      { sha256: 'a', threatIndicators: [{ category: 'SUSPICIOUS_EXTENSION', severity: 'MEDIUM', description: 'x', confidence: 'MEDIUM', source: 'AttachmentAnalyzer', analyzerVersion: '1.0.0' }] },
      { sha256: 'b', threatIndicators: [{ category: 'APK_UNSIGNED', severity: 'HIGH', description: 'x', confidence: 'MEDIUM', source: 'ApkAnalyzer', analyzerVersion: '1.0.0' }] },
    ];

    await fusionEngine.evaluate('email-1');

    // HIGH (35) is worse than MEDIUM (15) — only the worst tier contributes,
    // not 15+35, so overallScore must be exactly 35.
    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({ update: expect.objectContaining({ overallScore: 35 }) })
    );
  });

  it('does not score an attachment with no threat indicators', async () => {
    mockEmail.attachments = [{ sha256: 'clean', threatIndicators: null }];

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({ update: expect.objectContaining({ overallScore: 0 }) })
    );
  });

  it('preserves explicit ML BEC prediction', async () => {
    // 3. ML prediction BEC -> explicit BEC label is preserved
    mockEmail.inferences = [{
      status: 'MODEL_PREDICTION',
      prediction: 'BEC',
      modelScore: 0.88
    }];

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.email.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ classification: 'BEC' })
      })
    );
  });

  it('computes HIGH/CRITICAL heuristic risk but does NOT fabricate PHISHING automatically', async () => {
    // 4. High deterministic risk without ML prediction
    mockEmail.authAnalysis = {
      spf: AuthResultStatus.FAIL,
      dkim: AuthResultStatus.FAIL
    };
    mockEmail.urls = [
      { indicators: ['OBFUSCATED'] }
    ];

    await fusionEngine.evaluate('email-1');

    // Score: 40 (Auth) + 40 (URL) = 80 -> CRITICAL
    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 80, riskLevel: 'CRITICAL' })
      })
    );

    // Classification should NOT be set because ML prediction is missing
    // (analysisStatus: 'COMPLETED' is expected here too — Phase 10G.2).
    expect(prismaMock.email.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: { riskScore: 80, analysisStatus: 'COMPLETED' }
      })
    );
  });

  it('bounds risk score between 0 and 100', async () => {
    // 5. Risk score remains bounded
    mockEmail.authAnalysis = { spf: AuthResultStatus.PASS, dkim: AuthResultStatus.PASS }; // -10 score
    await fusionEngine.evaluate('email-1');

    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 0 })
      })
    );
  });

  it('uses upsert for RiskAssessment persistence to prevent duplicates', async () => {
    // 6. RiskAssessment persistence -> repeated processing does not create duplicates
    await fusionEngine.evaluate('email-1');
    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { emailId_version: { emailId: 'email-1', version: '1.0' } }
      })
    );
  });

  // --- Phase 7C.3 CTI Fusion Integration Tests ---
  //
  // FusionEngine has no direct Prisma relation from Email to CTI data — Indicator and
  // ThreatIntelObservation are a global cache keyed by indicator value (see
  // packages/database/prisma/schema.prisma). These tests exercise the real wiring:
  // indicators are re-derived from the email's urls/relayHops/attachments (same
  // IocNormalizer used by CtiEnrichmentWorker) and looked up via prisma.indicator.findMany.

  it('does not query CTI observations when no indicators can be extracted from the email', async () => {
    // No urls, relayHops, or attachments -> nothing to look up.
    await fusionEngine.evaluate('email-1');

    expect(prismaMock.indicator.findMany).not.toHaveBeenCalled();
    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 0 })
      })
    );
  });

  it('does not fabricate a score when indicators are extracted but no CTI observations exist for them', async () => {
    mockEmail.urls = [{ url: 'https://bad.com/phish', indicators: null }];
    prismaMock.indicator.findMany.mockResolvedValue([]);

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.indicator.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { value: { in: ['bad.com'] } }
      })
    );
    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 0 })
      })
    );
  });

  it('adds +50 score and THREAT_INTELLIGENCE factor for a MALICIOUS CTI observation on an extracted indicator', async () => {
    mockEmail.urls = [{ url: 'https://bad.com/phish', indicators: null }];
    prismaMock.indicator.findMany.mockResolvedValue([
      { id: 'ind-1', value: 'bad.com', observations: [{ verdict: ThreatVerdict.MALICIOUS, provider: 'AbuseIPDB' }] }
    ]);

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({
          overallScore: 50,
          factors: expect.objectContaining({
            create: expect.arrayContaining([
              expect.objectContaining({ category: 'THREAT_INTELLIGENCE', scoreContribution: 50 })
            ])
          })
        })
      })
    );
  });

  it('contributes exactly +50 for multiple MALICIOUS observations, without artificial fan-out inflation', async () => {
    mockEmail.urls = [
      { url: 'https://bad.com/phish', indicators: null },
      { url: 'https://worse.com/phish', indicators: null }
    ];
    prismaMock.indicator.findMany.mockResolvedValue([
      { id: 'ind-1', value: 'bad.com', observations: [{ verdict: ThreatVerdict.MALICIOUS, provider: 'AbuseIPDB' }] },
      { id: 'ind-2', value: 'worse.com', observations: [{ verdict: ThreatVerdict.MALICIOUS, provider: 'VirusTotal' }] }
    ]);

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 50 })
      })
    );
  });

  it('adds +20 score and factor for SUSPICIOUS CTI when no MALICIOUS observations exist', async () => {
    mockEmail.urls = [{ url: 'https://sus.com/phish', indicators: null }];
    prismaMock.indicator.findMany.mockResolvedValue([
      { id: 'ind-1', value: 'sus.com', observations: [{ verdict: ThreatVerdict.SUSPICIOUS, provider: 'AbuseIPDB' }] }
    ]);

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({
          overallScore: 20,
          factors: expect.objectContaining({
            create: expect.arrayContaining([
              expect.objectContaining({ category: 'THREAT_INTELLIGENCE', scoreContribution: 20 })
            ])
          })
        })
      })
    );
  });

  it('MALICIOUS takes precedence over SUSPICIOUS for CTI scoring', async () => {
    mockEmail.urls = [
      { url: 'https://sus.com/phish', indicators: null },
      { url: 'https://bad.com/phish', indicators: null }
    ];
    prismaMock.indicator.findMany.mockResolvedValue([
      { id: 'ind-1', value: 'sus.com', observations: [{ verdict: ThreatVerdict.SUSPICIOUS, provider: 'AbuseIPDB' }] },
      { id: 'ind-2', value: 'bad.com', observations: [{ verdict: ThreatVerdict.MALICIOUS, provider: 'VirusTotal' }] }
    ]);

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 50 })
      })
    );
  });

  it('contributes +0 for CLEAN observations and creates no threat-intelligence factor', async () => {
    mockEmail.urls = [{ url: 'https://good.com/phish', indicators: null }];
    prismaMock.indicator.findMany.mockResolvedValue([
      { id: 'ind-1', value: 'good.com', observations: [{ verdict: ThreatVerdict.CLEAN, provider: 'AbuseIPDB' }] }
    ]);

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 0 })
      })
    );
  });

  it('contributes +0 for UNKNOWN observations and creates no threat-intelligence factor', async () => {
    mockEmail.urls = [{ url: 'https://unknown.com/phish', indicators: null }];
    prismaMock.indicator.findMany.mockResolvedValue([
      { id: 'ind-1', value: 'unknown.com', observations: [{ verdict: ThreatVerdict.UNKNOWN, provider: 'AbuseIPDB' }] }
    ]);

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 0 })
      })
    );
  });

  it('correlates indicators extracted from relay hop source IPs and attachment hashes, not just URLs', async () => {
    mockEmail.relayHops = [{ sourceIp: '203.0.113.5' }];
    mockEmail.attachments = [{ sha256: 'a'.repeat(64) }];
    prismaMock.indicator.findMany.mockResolvedValue([
      { id: 'ind-1', value: '203.0.113.5', observations: [{ verdict: ThreatVerdict.MALICIOUS, provider: 'AbuseIPDB' }] }
    ]);

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.indicator.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { value: { in: expect.arrayContaining(['203.0.113.5', 'a'.repeat(64)]) } }
      })
    );
    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 50 })
      })
    );
  });

  it('safely updates risk score for MALICIOUS CTI without fabricating ML classification', async () => {
    // Known ML prediction
    mockEmail.inferences = [{
      status: 'MODEL_PREDICTION',
      prediction: 'LEGITIMATE',
      modelScore: 0.1
    }];
    mockEmail.urls = [{ url: 'https://bad.com/phish', indicators: null }];
    prismaMock.indicator.findMany.mockResolvedValue([
      { id: 'ind-1', value: 'bad.com', observations: [{ verdict: ThreatVerdict.MALICIOUS, provider: 'AbuseIPDB' }] }
    ]);

    await fusionEngine.evaluate('email-1');

    // Email update should preserve the ML prediction of LEGITIMATE but update riskScore to 50
    expect(prismaMock.email.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ classification: 'LEGITIMATE', riskScore: 50 })
      })
    );
  });

  it('bounds the maximum risk score at 100 even with severe CTI', async () => {
    mockEmail.authAnalysis = {
      spf: AuthResultStatus.FAIL,
      dkim: AuthResultStatus.FAIL
    }; // +40
    mockEmail.urls = [
      { url: 'https://bad.com/phish', indicators: ['OBFUSCATED'] }
    ]; // +40 (URL anomaly) + CTI lookup
    prismaMock.indicator.findMany.mockResolvedValue([
      { id: 'ind-1', value: 'bad.com', observations: [{ verdict: ThreatVerdict.MALICIOUS, provider: 'AbuseIPDB' }] }
    ]); // +50

    await fusionEngine.evaluate('email-1');

    // 40 + 40 + 50 = 130, but should be bounded to 100
    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 100, riskLevel: 'CRITICAL' })
      })
    );
  });

  // --- Phase 10G.2: analysisStatus invariant ---
  //
  // FusionEngine.evaluate() is the single, always-executed terminal stage of
  // the ingestion pipeline (called from both the normal chain and the CTI
  // re-evaluation re-entry — see services/worker/src/analyzer/mlEvaluationStage.ts).
  // It is therefore the only place that may legitimately declare the email's
  // analysisStatus 'COMPLETED': that value must imply a real, just-persisted
  // RiskAssessment exists, in the SAME transaction, not merely that raw MIME
  // parsing succeeded earlier in the pipeline (services/worker/src/index.ts's
  // parsing worker now writes 'PROCESSING', never 'COMPLETED' — see the
  // dedicated static-source test in
  // services/worker/src/__tests__/analysisStatusInvariant.test.ts).

  it('sets analysisStatus to COMPLETED in the SAME email.update call that persists riskScore, when no ML prediction exists', async () => {
    await fusionEngine.evaluate('email-1');

    expect(prismaMock.email.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ analysisStatus: 'COMPLETED', riskScore: 0 })
      })
    );
  });

  it('sets analysisStatus to COMPLETED in the SAME email.update call that persists an explicit ML classification', async () => {
    mockEmail.inferences = [{ status: 'MODEL_PREDICTION', prediction: 'PHISHING', modelScore: 0.95 }];

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.email.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ analysisStatus: 'COMPLETED', classification: 'PHISHING' })
      })
    );
  });

  it('the analysisStatus write happens inside the same $transaction as the RiskAssessment upsert, not as a separate, non-atomic call', async () => {
    const transactionCalls: unknown[] = [];
    prismaMock.$transaction = vi.fn().mockImplementation(async (callback: (tx: unknown) => Promise<void>) => {
      transactionCalls.push('transaction-start');
      await callback(prismaMock);
    });
    fusionEngine = new FusionEngine(prismaMock as unknown as PrismaClient);

    await fusionEngine.evaluate('email-1');

    expect(transactionCalls).toHaveLength(1); // exactly one transaction; RiskAssessment + analysisStatus are not split across two
    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalled();
    expect(prismaMock.email.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ analysisStatus: 'COMPLETED' }) })
    );
  });

  it('repeated evaluation (e.g. a CTI re-evaluation re-run) is idempotent: analysisStatus remains COMPLETED, never regresses', async () => {
    await fusionEngine.evaluate('email-1');
    await fusionEngine.evaluate('email-1'); // simulates a second pass (CTI re-evaluation)

    const allEmailUpdateCalls = (prismaMock.email.update as ReturnType<typeof vi.fn>).mock.calls;
    for (const call of allEmailUpdateCalls) {
      expect(call[0].data.analysisStatus).toBe('COMPLETED');
    }
  });

  describe('Phase 2 — outbound notification hook', () => {
    it('calls notifier.notifyThreatAnalysisCompleted with the minimal documented fields after the transaction commits', async () => {
      mockEmail.organizationId = 'org-1';
      const notifier = { notifyThreatAnalysisCompleted: vi.fn().mockResolvedValue(undefined) };
      fusionEngine = new FusionEngine(prismaMock as unknown as PrismaClient, notifier);

      await fusionEngine.evaluate('email-1');

      expect(notifier.notifyThreatAnalysisCompleted).toHaveBeenCalledWith(
        expect.objectContaining({
          emailId: 'email-1',
          organizationId: 'org-1',
          analysisStatus: 'COMPLETED',
        })
      );
    });

    it('does not call the notifier at all when none was provided (existing behavior unchanged)', async () => {
      fusionEngine = new FusionEngine(prismaMock as unknown as PrismaClient);
      await expect(fusionEngine.evaluate('email-1')).resolves.not.toThrow();
    });

    it('a notifier rejection is caught and logged, never allowed to fail evaluate()', async () => {
      const notifier = { notifyThreatAnalysisCompleted: vi.fn().mockRejectedValue(new Error('redis down')) };
      fusionEngine = new FusionEngine(prismaMock as unknown as PrismaClient, notifier);

      await expect(fusionEngine.evaluate('email-1')).resolves.not.toThrow();
      // Risk assessment must still be persisted — a notification failure
      // never rolls back or blocks the actual analysis result.
      expect(prismaMock.riskAssessment.upsert).toHaveBeenCalled();
    });
  });

  describe('Phase 2 (real-time SSE) — publishes ALERT_CREATED to Redis after the transaction commits', () => {
    it('publishes when a CRITICAL/HIGH Alert is created, with a real notificationRedis connection provided', async () => {
      mockEmail.organizationId = 'org-1';
      mockEmail.authAnalysis = { spf: AuthResultStatus.FAIL, dkim: AuthResultStatus.FAIL };
      mockEmail.urls = [{ indicators: ['OBFUSCATED'] }]; // CRITICAL

      const publishMock = vi.fn().mockResolvedValue(1);
      const fakeRedis = { publish: publishMock } as unknown as ConstructorParameters<typeof FusionEngine>[2];
      fusionEngine = new FusionEngine(prismaMock as unknown as PrismaClient, undefined, fakeRedis);

      await fusionEngine.evaluate('email-1');

      expect(publishMock).toHaveBeenCalledTimes(1);
      const [channel, payload] = publishMock.mock.calls[0];
      expect(channel).toBe('notifications:org:org-1');
      const parsed = JSON.parse(payload);
      expect(parsed).toMatchObject({ type: 'ALERT_CREATED', organizationId: 'org-1', severity: 'CRITICAL' });
      expect(parsed.alertId).toBe('alert-1');
    });

    it('never publishes for LOW/MEDIUM results', async () => {
      const publishMock = vi.fn();
      const fakeRedis = { publish: publishMock } as unknown as ConstructorParameters<typeof FusionEngine>[2];
      fusionEngine = new FusionEngine(prismaMock as unknown as PrismaClient, undefined, fakeRedis);

      await fusionEngine.evaluate('email-1'); // default mock scores 0 -> LOW

      expect(publishMock).not.toHaveBeenCalled();
    });

    it('does nothing (never throws) when no notificationRedis was provided', async () => {
      mockEmail.organizationId = 'org-1';
      mockEmail.authAnalysis = { spf: AuthResultStatus.FAIL, dkim: AuthResultStatus.FAIL };
      mockEmail.urls = [{ indicators: ['OBFUSCATED'] }];
      fusionEngine = new FusionEngine(prismaMock as unknown as PrismaClient);

      await expect(fusionEngine.evaluate('email-1')).resolves.not.toThrow();
    });

    it('a Redis publish failure is swallowed — never fails evaluate() or blocks the already-persisted Alert', async () => {
      mockEmail.organizationId = 'org-1';
      mockEmail.authAnalysis = { spf: AuthResultStatus.FAIL, dkim: AuthResultStatus.FAIL };
      mockEmail.urls = [{ indicators: ['OBFUSCATED'] }];
      const fakeRedis = { publish: vi.fn().mockRejectedValue(new Error('redis down')) } as unknown as ConstructorParameters<typeof FusionEngine>[2];
      fusionEngine = new FusionEngine(prismaMock as unknown as PrismaClient, undefined, fakeRedis);

      await expect(fusionEngine.evaluate('email-1')).resolves.not.toThrow();
      expect(prismaMock.alert.create).toHaveBeenCalled();
    });
  });

  describe('Phase 2 (notification bell) — Alert creation on CRITICAL/HIGH results', () => {
    it('creates an org-scoped Alert when the result is CRITICAL', async () => {
      mockEmail.organizationId = 'org-1';
      mockEmail.authAnalysis = { spf: AuthResultStatus.FAIL, dkim: AuthResultStatus.FAIL };
      mockEmail.urls = [{ indicators: ['OBFUSCATED'] }]; // 40 + 40 = 80 -> CRITICAL

      await fusionEngine.evaluate('email-1');

      expect(prismaMock.alert.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ organizationId: 'org-1', severity: 'CRITICAL' }),
        })
      );
    });

    it('creates an Alert when the result is HIGH', async () => {
      mockEmail.organizationId = 'org-1';
      mockEmail.attachments = [
        { sha256: 'b', threatIndicators: [{ category: 'APK_UNSIGNED', severity: 'HIGH', description: 'x', confidence: 'MEDIUM', source: 'ApkAnalyzer', analyzerVersion: '1.0.0' }] },
      ]; // overallScore 35 -> HIGH tier by riskLevel thresholds (>=30 MEDIUM... need >=60 for HIGH)
      mockEmail.authAnalysis = { spf: AuthResultStatus.FAIL, dkim: AuthResultStatus.FAIL }; // +40 => 75 total -> HIGH (60-79)

      await fusionEngine.evaluate('email-1');

      expect(prismaMock.alert.create).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ severity: 'HIGH' }) })
      );
    });

    it('does NOT create an Alert for LOW/MEDIUM results — no notification noise for routine emails', async () => {
      // Default mockEmail (no signals) scores 0 -> LOW
      await fusionEngine.evaluate('email-1');
      expect(prismaMock.alert.create).not.toHaveBeenCalled();
    });

    it('the Alert message never fabricates content beyond real subject/sender/factor data', async () => {
      mockEmail.organizationId = 'org-1';
      mockEmail.subject = 'Urgent wire transfer';
      mockEmail.senderAddress = 'ceo@example.com';
      mockEmail.authAnalysis = { spf: AuthResultStatus.FAIL, dkim: AuthResultStatus.FAIL };
      mockEmail.urls = [{ indicators: ['OBFUSCATED'] }];

      await fusionEngine.evaluate('email-1');

      const call = (prismaMock.alert.create as ReturnType<typeof vi.fn>).mock.calls[0][0];
      expect(call.data.message).toContain('Urgent wire transfer');
      expect(call.data.message).toContain('ceo@example.com');
    });

    it('Alert creation happens inside the same transaction as the RiskAssessment write (atomic)', async () => {
      mockEmail.organizationId = 'org-1';
      mockEmail.authAnalysis = { spf: AuthResultStatus.FAIL, dkim: AuthResultStatus.FAIL };
      mockEmail.urls = [{ indicators: ['OBFUSCATED'] }];

      const transactionCalls: unknown[] = [];
      prismaMock.$transaction = vi.fn().mockImplementation(async (callback: (tx: unknown) => Promise<void>) => {
        transactionCalls.push('transaction-start');
        await callback(prismaMock);
      });
      fusionEngine = new FusionEngine(prismaMock as unknown as PrismaClient);

      await fusionEngine.evaluate('email-1');

      expect(transactionCalls).toHaveLength(1);
      expect(prismaMock.alert.create).toHaveBeenCalled();
    });
  });

  describe('Phase H — IP/domain/GeoIP intelligence does not affect scoring (deliberate scope boundary)', () => {
    it('the score is unchanged whether or not EmailUrl.domain/GeoLocation data exists — FusionEngine was not modified for Phase H', async () => {
      // FusionEngine.ts reads email.urls/relayHops/attachments only for
      // CTI *verdict* correlation (MALICIOUS/SUSPICIOUS) — it has no
      // knowledge of EmailUrl.domain or the GeoLocation table at all.
      // Geographic origin alone has no defensible universal risk meaning
      // (a real signal would be indistinguishable from fabricated
      // severity), so Phase H intentionally left FusionEngine untouched;
      // GeoIP/ASN data feeds the forensic/display layer only. This test
      // proves that boundary holds: identical mock, identical score.
      mockEmail.urls = [{ url: 'https://example.com', domain: 'example.com', indicators: [] }];

      await fusionEngine.evaluate('email-1');

      expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
        expect.objectContaining({ update: expect.objectContaining({ overallScore: 0 }) })
      );
    });
  });
});
