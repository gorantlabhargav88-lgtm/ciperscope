import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('@ciperscope/database', () => {
  class FakePrismaClientKnownRequestError extends Error {
    code: string;
    constructor(message: string, code: string) {
      super(message);
      this.code = code;
    }
  }
  return {
    WebhookDeliveryStatus: { PENDING: 'PENDING', SUCCESS: 'SUCCESS', FAILED: 'FAILED', EXHAUSTED: 'EXHAUSTED' },
    Prisma: { PrismaClientKnownRequestError: FakePrismaClientKnownRequestError },
  };
});

vi.mock('@ciperscope/config', () => ({
  env: { NODE_ENV: 'test' },
  decryptToken: vi.fn(() => 'plaintext-webhook-secret'),
  requireGmailTokenEncryptionKey: vi.fn(() => 'fake-key'),
}));

vi.mock('@ciperscope/logger', () => ({ logger: { info: vi.fn(), error: vi.fn(), warn: vi.fn() } }));

import { processWebhookDelivery } from '../WebhookDeliveryWorker';
import { logger } from '@ciperscope/logger';
import { Prisma } from '@ciperscope/database';
import { signWebhookPayload } from '../webhookSigning';

function makePrismaMock(overrides: any = {}) {
  return {
    webhook: {
      findUnique: vi.fn().mockResolvedValue({
        id: 'wh-1', organizationId: 'org-1', url: 'http://localhost:9999/receive',
        secretEncrypted: 'encrypted:xyz', enabled: true, events: ['THREAT_ANALYSIS_COMPLETED'],
      }),
    },
    webhookDelivery: {
      findUnique: vi.fn().mockResolvedValue(null),
      create: vi.fn().mockResolvedValue({}),
      update: vi.fn().mockResolvedValue({}),
      upsert: vi.fn().mockResolvedValue({}),
    },
    ...overrides,
  };
}

function makeJob(overrides: any = {}) {
  return {
    data: {
      organizationId: 'org-1',
      webhookId: 'wh-1',
      eventId: 'event-1',
      eventType: 'THREAT_ANALYSIS_COMPLETED',
      payload: { eventType: 'THREAT_ANALYSIS_COMPLETED', eventId: 'event-1', threatScore: 40 },
    },
    attemptsMade: 0,
    opts: { attempts: 3 },
    ...overrides,
  };
}

describe('processWebhookDelivery', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('A. delivers successfully on a 200 response and records SUCCESS', async () => {
    fetchMock.mockResolvedValue({ ok: true, status: 200 });
    const prisma = makePrismaMock();

    await processWebhookDelivery(prisma as any, makeJob());

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(prisma.webhookDelivery.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: 'SUCCESS', lastStatusCode: 200 }) })
    );
  });

  it('B. records FAILED and throws on a non-2xx response', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 500 });
    const prisma = makePrismaMock();

    await expect(processWebhookDelivery(prisma as any, makeJob())).rejects.toThrow(/status 500/);
    expect(prisma.webhookDelivery.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: 'FAILED', lastStatusCode: 500 }) })
    );
  });

  it('C. records FAILED with a safe message and throws on a timeout (AbortError), never leaking the secret', async () => {
    const abortError = new Error('The operation was aborted');
    abortError.name = 'AbortError';
    fetchMock.mockRejectedValue(abortError);
    const prisma = makePrismaMock();

    await expect(processWebhookDelivery(prisma as any, makeJob())).rejects.toThrow();
    expect(prisma.webhookDelivery.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: 'FAILED', lastError: 'Request timed out' }) })
    );
  });

  it('D/E. marks EXHAUSTED only on the final configured attempt, not earlier ones', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 503 });
    const prisma = makePrismaMock();

    // attemptsMade=0 with attempts:3 -> this is attempt 1 of 3, not final.
    await expect(processWebhookDelivery(prisma as any, makeJob({ attemptsMade: 0, opts: { attempts: 3 } }))).rejects.toThrow();
    expect(prisma.webhookDelivery.update).not.toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: 'EXHAUSTED' }) })
    );

    vi.clearAllMocks();
    fetchMock.mockResolvedValue({ ok: false, status: 503 });
    const prisma2 = makePrismaMock();
    // attemptsMade=2 with attempts:3 -> this is attempt 3 of 3, final.
    await expect(processWebhookDelivery(prisma2 as any, makeJob({ attemptsMade: 2, opts: { attempts: 3 } }))).rejects.toThrow();
    expect(prisma2.webhookDelivery.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ status: 'EXHAUSTED' }) })
    );
  });

  it('F. signs the exact transmitted payload with the decrypted webhook secret', async () => {
    fetchMock.mockResolvedValue({ ok: true, status: 200 });
    const prisma = makePrismaMock();
    const job = makeJob();

    await processWebhookDelivery(prisma as any, job);

    const [, options] = fetchMock.mock.calls[0];
    const expectedSignature = signWebhookPayload(JSON.stringify(job.data.payload), 'plaintext-webhook-secret');
    expect(options.headers['X-CipherScope-Signature']).toBe(expectedSignature);
    expect(options.body).toBe(JSON.stringify(job.data.payload));
  });

  it('G/N. is idempotent — an event already marked SUCCESS is never re-delivered', async () => {
    const prisma = makePrismaMock({
      webhookDelivery: {
        findUnique: vi.fn().mockResolvedValue({ status: 'SUCCESS' }),
        create: vi.fn(),
        update: vi.fn(),
      },
    });

    await processWebhookDelivery(prisma as any, makeJob());

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('N. a concurrent duplicate create (unique constraint P2002) is treated as already-handled, not an error', async () => {
    const prisma = makePrismaMock({
      webhookDelivery: {
        findUnique: vi.fn().mockResolvedValue(null),
        create: vi.fn().mockRejectedValue(new (Prisma as any).PrismaClientKnownRequestError('duplicate', 'P2002')),
        update: vi.fn(),
      },
    });

    await processWebhookDelivery(prisma as any, makeJob());

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('H. a disabled webhook is skipped without attempting delivery', async () => {
    const prisma = makePrismaMock();
    prisma.webhook.findUnique.mockResolvedValue({
      id: 'wh-1', organizationId: 'org-1', url: 'http://localhost:9999/receive',
      secretEncrypted: 'encrypted:xyz', enabled: false, events: ['THREAT_ANALYSIS_COMPLETED'],
    });

    await processWebhookDelivery(prisma as any, makeJob());

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('I. tenant isolation — a webhook lookup is scoped to (id, organizationId); a mismatched org finds nothing', async () => {
    const prisma = makePrismaMock();
    prisma.webhook.findUnique.mockResolvedValue(null); // simulates no row for this org+id combination

    await processWebhookDelivery(prisma as any, makeJob({ data: { ...makeJob().data, organizationId: 'org-attacker' } }));

    expect(prisma.webhook.findUnique).toHaveBeenCalledWith({
      where: { id_organizationId: { id: 'wh-1', organizationId: 'org-attacker' } },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('J. the webhook secret never appears in any logger call', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 502 });
    const prisma = makePrismaMock();

    await expect(processWebhookDelivery(prisma as any, makeJob())).rejects.toThrow();

    const allLogCalls = [
      ...(logger.info as any).mock.calls,
      ...(logger.warn as any).mock.calls,
      ...(logger.error as any).mock.calls,
    ];
    const serialized = JSON.stringify(allLogCalls);
    expect(serialized).not.toContain('plaintext-webhook-secret');
    expect(serialized).not.toContain('encrypted:xyz');
  });

  it('K. never sends an Authorization header or any OAuth field in the outbound request', async () => {
    fetchMock.mockResolvedValue({ ok: true, status: 200 });
    const prisma = makePrismaMock();

    await processWebhookDelivery(prisma as any, makeJob());

    const [, options] = fetchMock.mock.calls[0];
    expect(options.headers['Authorization']).toBeUndefined();
    expect(JSON.stringify(options.headers).toLowerCase()).not.toContain('bearer');
  });
});
