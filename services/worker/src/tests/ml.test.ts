import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MLClassifier } from '../classifier/MLClassifier';
import { PrismaClient } from '@ciperscope/database';
import { LocalRawEmailStore } from '@ciperscope/storage';

// Mock dependencies
const prismaMock = {
  email: { findUnique: vi.fn(), update: vi.fn() },
  mLInference: { create: vi.fn(), findFirst: vi.fn() },
} as unknown as PrismaClient;

const rawStoreMock = {
  get: vi.fn(),
  exists: vi.fn()
} as unknown as LocalRawEmailStore;

const DUMMY_EMAIL = {
  id: 'email-1',
  organizationId: 'org-1',
  rawStorageKey: 'key-1',
  headers: [
    { name: 'Subject', value: 'Test Subject' }
  ],
  addresses: [
    { headerName: 'From', address: 'attacker@evil.com' }
  ]
};

global.fetch = vi.fn();

describe('Phase 11 ML Classifier Integration Tests', () => {
  let classifier: MLClassifier;

  beforeEach(() => {
    vi.clearAllMocks();
    classifier = new MLClassifier(prismaMock, rawStoreMock, 'http://ml-worker:8000', 'internal-secret-token');
    // @ts-expect-error: mock
    (prismaMock.email.findUnique).mockResolvedValue(DUMMY_EMAIL);
    // @ts-expect-error: mock
    (rawStoreMock.get).mockResolvedValue(Buffer.from('fake raw email'));
  });

  it('handles ML service unavailable (connection refused)', async () => {
    // @ts-expect-error: mock
    (global.fetch).mockRejectedValueOnce(new Error('fetch failed'));

    await classifier.classifyEmail('email-1');

    expect(prismaMock.mLInference.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          status: 'FAILED',
          explanation: 'fetch failed'
        })
      })
    );
  });

  it('handles MODEL_NOT_AVAILABLE graceful degradation', async () => {
    // @ts-expect-error: mock
    (global.fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: 'NOT_AVAILABLE',
        predictedLabel: null,
        modelScore: null,
        modelName: null,
        modelVersion: null,
        artifactSha256: null,
        tokenizerVersion: null,
        preprocessingVersion: '1.0',
        inferenceTimestamp: new Date().toISOString(),
        serviceVersion: '1.0.0'
      })
    });

    await classifier.classifyEmail('email-1');

    expect(prismaMock.mLInference.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          status: 'NOT_AVAILABLE',
          prediction: null
        })
      })
    );
  });

  it('validates successful response contract (MOCK PROVER)', async () => {
    // Note: Mock provider used for testing contract. Not real inference.
    // @ts-expect-error: mock
    (global.fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: 'SUCCESS',
        predictedLabel: 'PHISHING',
        modelScore: 0.95,
        modelName: 'CiperScope-DistilBERT',
        modelVersion: 'v1.0.0',
        artifactSha256: 'deadbeef',
        tokenizerVersion: '1.0',
        preprocessingVersion: '1.0',
        inferenceTimestamp: new Date().toISOString(),
        serviceVersion: '1.0.0'
      })
    });

    await classifier.classifyEmail('email-1');

    expect(prismaMock.mLInference.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          status: 'SUCCESS',
          prediction: 'PHISHING',
          modelScore: 0.95,
          artifactSha256: 'deadbeef'
        })
      })
    );
  });

  it('handles malformed ML response', async () => {
    // @ts-expect-error: mock
    (global.fetch).mockResolvedValueOnce({
      ok: false,
      status: 400
    });

    await classifier.classifyEmail('email-1');

    expect(prismaMock.mLInference.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          status: 'FAILED',
          explanation: 'ML Service returned HTTP 400'
        })
      })
    );
  });

  it('handles timeout', async () => {
    // @ts-expect-error: mock
    (global.fetch).mockResolvedValueOnce({
      ok: false,
      status: 504
    });

    await classifier.classifyEmail('email-1');

    expect(prismaMock.mLInference.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          status: 'TIMEOUT'
        })
      })
    );
  });
});
