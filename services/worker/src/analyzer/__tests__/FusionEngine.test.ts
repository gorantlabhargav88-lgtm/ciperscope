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
      inferences: [],
      threatIndicators: [],
      geolocationInfo: []
    };

    prismaMock = {
      email: {
        findUnique: vi.fn().mockResolvedValue(mockEmail),
        update: vi.fn().mockResolvedValue({})
      },
      $transaction: vi.fn().mockImplementation(async (callback) => {
        // Execute the callback with the mock Prisma client (which has riskAssessment mocked)
        await callback(prismaMock);
      }),
      riskAssessment: {
        upsert: vi.fn().mockResolvedValue({ id: 'ra-1' })
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
    expect(prismaMock.email.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: { riskScore: 80 }
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

  // --- Phase 14.4 CTI Integration Tests ---

  it('adds +50 score and THREAT_INTELLIGENCE factor for MALICIOUS CTI', async () => {
    mockEmail.threatIndicators = [
      { status: ThreatVerdict.MALICIOUS, iocValue: 'bad.com', provider: 'Mock' }
    ];

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

  it('contributes exactly +50 for multiple MALICIOUS indicators, without artificial fan-out inflation', async () => {
    mockEmail.threatIndicators = [
      { status: ThreatVerdict.MALICIOUS, iocValue: 'bad.com', provider: 'Mock' },
      { status: ThreatVerdict.MALICIOUS, iocValue: 'worse.com', provider: 'Mock' }
    ];

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 50 })
      })
    );
  });

  it('adds +20 score and factor for SUSPICIOUS CTI when no MALICIOUS indicators exist', async () => {
    mockEmail.threatIndicators = [
      { status: ThreatVerdict.SUSPICIOUS, iocValue: 'sus.com', provider: 'Mock' }
    ];

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
    mockEmail.threatIndicators = [
      { status: ThreatVerdict.SUSPICIOUS, iocValue: 'sus.com', provider: 'Mock' },
      { status: ThreatVerdict.MALICIOUS, iocValue: 'bad.com', provider: 'Mock' }
    ];

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 50 })
      })
    );
  });

  it('contributes +0 for CLEAN indicators and creates no threat-intelligence factor', async () => {
    mockEmail.threatIndicators = [
      { status: ThreatVerdict.CLEAN, iocValue: 'good.com', provider: 'Mock' }
    ];

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 0 })
      })
    );
  });

  it('contributes +0 for UNKNOWN/missing indicators and creates no threat-intelligence factor', async () => {
    mockEmail.threatIndicators = [
      { status: ThreatVerdict.UNKNOWN, iocValue: 'unknown.com', provider: 'Mock' }
    ];

    await fusionEngine.evaluate('email-1');

    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 0 })
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
    mockEmail.threatIndicators = [
      { status: ThreatVerdict.MALICIOUS, iocValue: 'bad.com', provider: 'Mock' }
    ];

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
      { indicators: ['OBFUSCATED'] }
    ]; // +40
    mockEmail.threatIndicators = [
      { status: ThreatVerdict.MALICIOUS, iocValue: 'bad.com', provider: 'Mock' }
    ]; // +50

    await fusionEngine.evaluate('email-1');

    // 40 + 40 + 50 = 130, but should be bounded to 100
    expect(prismaMock.riskAssessment.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({ overallScore: 100, riskLevel: 'CRITICAL' })
      })
    );
  });
});
