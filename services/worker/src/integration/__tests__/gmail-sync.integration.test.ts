import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import crypto from 'crypto';
import os from 'os';
import path from 'path';
import fs from 'fs';
import { prisma } from '@ciperscope/database';
import { env, encryptToken } from '@ciperscope/config';
import { LocalRawEmailStore } from '@ciperscope/storage';
import { QueueManager } from '@ciperscope/queue';
import { logger } from '@ciperscope/logger';

/**
 * Phase 10B — services/worker/src/integration/gmail-sync.ts had zero
 * automated test coverage (confirmed by repo-wide search before writing
 * this file). This exercises the REAL worker logic against real
 * Postgres + Redis (the only two infra dependencies it has), with the
 * external Google API boundary mocked — that's the only boundary that
 * cannot be tested against a real account safely or deterministically.
 */

const historyListMock = vi.fn();
const messagesGetMock = vi.fn();
const setCredentialsMock = vi.fn();
const onTokensMock = vi.fn();

vi.mock('googleapis', () => {
  return {
    google: {
      auth: {
        OAuth2: vi.fn().mockImplementation(() => ({
          setCredentials: setCredentialsMock,
          on: onTokensMock
        }))
      },
      gmail: vi.fn().mockImplementation(() => ({
        users: {
          history: { list: historyListMock },
          messages: { get: messagesGetMock }
        }
      }))
    }
  };
});

// Imported after the mock so it picks up the mocked googleapis module.
const { GmailSyncWorker } = await import('../gmail-sync');

const ENCRYPTION_KEY = env.GMAIL_TOKEN_ENCRYPTION_KEY!;

function rawEmailBase64Url(content: string): string {
  return Buffer.from(content, 'utf-8').toString('base64url');
}

function sha256Of(content: string): string {
  return crypto.createHash('sha256').update(Buffer.from(content, 'utf-8')).digest('hex');
}

describe('GmailSyncWorker.process (Integration — real Postgres + Redis, mocked Google API)', () => {
  let orgA: string;
  let orgB: string;
  let integrationAId: string;
  let integrationBId: string;
  let emailAddressA: string;
  let emailAddressB: string;
  let rawEmailStore: LocalRawEmailStore;
  let worker: InstanceType<typeof GmailSyncWorker>;
  let queueManager: QueueManager;
  let storeDir: string;
  const createdEmailIds: string[] = [];
  const createdJobIds: string[] = [];
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeAll(async () => {
    if (!ENCRYPTION_KEY) {
      throw new Error('GMAIL_TOKEN_ENCRYPTION_KEY must be set to run this test suite (see .env.example)');
    }

    storeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-sync-test-'));
    rawEmailStore = new LocalRawEmailStore(storeDir);
    worker = new GmailSyncWorker(rawEmailStore);
    queueManager = new QueueManager(env.REDIS_URL);

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    emailAddressA = `worker-test-a-${crypto.randomUUID()}@example.com`;
    emailAddressB = `worker-test-b-${crypto.randomUUID()}@example.com`;

    await prisma.organization.createMany({
      data: [
        { id: orgA, name: 'Gmail Worker Test Org A' },
        { id: orgB, name: 'Gmail Worker Test Org B' }
      ]
    });

    const integrationA = await prisma.integration.create({
      data: {
        organizationId: orgA,
        provider: 'GMAIL',
        emailAddress: emailAddressA,
        accessToken: encryptToken('real-access-token-value-A', ENCRYPTION_KEY),
        refreshToken: encryptToken('real-refresh-token-value-A', ENCRYPTION_KEY),
        expiresAt: new Date(Date.now() + 3600_000),
        historyId: '100',
        status: 'ACTIVE'
      }
    });
    integrationAId = integrationA.id;

    const integrationB = await prisma.integration.create({
      data: {
        organizationId: orgB,
        provider: 'GMAIL',
        emailAddress: emailAddressB,
        accessToken: encryptToken('real-access-token-value-B', ENCRYPTION_KEY),
        refreshToken: encryptToken('real-refresh-token-value-B', ENCRYPTION_KEY),
        expiresAt: new Date(Date.now() + 3600_000),
        historyId: '200',
        status: 'ACTIVE'
      }
    });
    integrationBId = integrationB.id;
  });

  afterAll(async () => {
    for (const jobId of createdJobIds) {
      try {
        const job = await queueManager.getQueue('email-processing').getJob(jobId);
        await job?.remove();
      } catch { /* best-effort cleanup */ }
    }
    await prisma.email.deleteMany({ where: { id: { in: createdEmailIds } } });
    await prisma.integration.deleteMany({ where: { id: { in: [integrationAId, integrationBId] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await queueManager.closeAll();
    fs.rmSync(storeDir, { recursive: true, force: true });
  });

  beforeEach(async () => {
    vi.clearAllMocks();
    // Reset to the fixture baseline before each test — including tokens, since some
    // tests (e.g. token-refresh persistence, corrupted-envelope) deliberately mutate them.
    await prisma.integration.update({
      where: { id: integrationAId },
      data: {
        historyId: '100',
        status: 'ACTIVE',
        accessToken: encryptToken('real-access-token-value-A', ENCRYPTION_KEY),
        refreshToken: encryptToken('real-refresh-token-value-A', ENCRYPTION_KEY)
      }
    });
    logSpy = vi.spyOn(logger, 'info');
    vi.spyOn(logger, 'warn');
    vi.spyOn(logger, 'error');
  });

  async function trackEmail(emailId: string) {
    createdEmailIds.push(emailId);
  }

  /** Every logger.info/warn/error call made so far in the current test, serialized. */
  function allLoggedText(): string {
    return JSON.stringify([
      ...(logger.info as ReturnType<typeof vi.fn>).mock.calls,
      ...(logger.warn as ReturnType<typeof vi.fn>).mock.calls,
      ...(logger.error as ReturnType<typeof vi.fn>).mock.calls
    ]);
  }

  function assertNoSecretLeakage(): void {
    const text = allLoggedText();
    expect(text).not.toContain('real-access-token-value-A');
    expect(text).not.toContain('real-refresh-token-value-A');
    expect(text).not.toMatch(/Bearer\s+\S/i);
    expect(text.toLowerCase()).not.toContain('authorization');
  }

  // --- A. Successful synchronization ---

  it('A: a successful sync fetches history from the stored historyId, retrieves raw MIME, and enqueues a real ingestion job', async () => {
    const rawContent = `From: sender@example.com\r\nTo: ${emailAddressA}\r\nSubject: Test A\r\n\r\nBody A`;
    historyListMock.mockResolvedValue({ data: { history: [{ messagesAdded: [{ message: { id: 'msgA1' } }] }], historyId: '150' } });
    messagesGetMock.mockResolvedValue({ data: { raw: rawEmailBase64Url(rawContent) } });

    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '150' });

    // Uses the stored historyId as the sync cursor (incremental, not a full rescan).
    expect(historyListMock).toHaveBeenCalledWith({ userId: 'me', startHistoryId: '100', historyTypes: ['messageAdded'] });
    expect(messagesGetMock).toHaveBeenCalledWith({ userId: 'me', id: 'msgA1', format: 'raw' });

    const sha256 = sha256Of(rawContent);
    const emailRow = await prisma.email.findFirst({ where: { sha256, organizationId: orgA } });
    expect(emailRow).not.toBeNull();
    expect(emailRow!.organizationId).toBe(orgA);
    await trackEmail(emailRow!.id);

    const storedRaw = await rawEmailStore.get(emailRow!.rawStorageKey!);
    const chunks: Buffer[] = [];
    for await (const chunk of storedRaw) chunks.push(chunk as Buffer);
    expect(Buffer.concat(chunks).toString('utf-8')).toBe(rawContent);

    const jobId = `ingest-${emailRow!.id}`;
    createdJobIds.push(jobId);
    const job = await queueManager.getQueue('email-processing').getJob(jobId);
    expect(job).toBeDefined();
    expect(job!.data.organizationId).toBe(orgA);
    expect(job!.data.rawSha256).toBe(sha256);
    expect(job!.data.source).toBe('GMAIL');
    // The ingestion job payload must never carry OAuth material — only these fields.
    expect(Object.keys(job!.data).sort()).toEqual(
      ['emailId', 'jobId', 'operation', 'organizationId', 'rawSha256', 'requestId', 'resourceId', 'source', 'storageReference'].sort()
    );
  });

  // --- Defect regression: authoritative historyId ---

  it('B/DEFECT: persists Gmail\'s own authoritative historyId from the API response, not the job payload\'s (unvalidated) newHistoryId', async () => {
    historyListMock.mockResolvedValue({ data: { history: [], historyId: '999-authoritative' } });

    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '111-stale-or-spoofed' });

    const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
    expect(updated!.historyId).toBe('999-authoritative');
  });

  // --- C. Empty/no-op sync ---

  it('C: an empty history produces no ingestion job, and the worker exits cleanly while still advancing historyId', async () => {
    historyListMock.mockResolvedValue({ data: { history: [], historyId: '160' } });

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '160' })
    ).resolves.toBeUndefined();

    expect(messagesGetMock).not.toHaveBeenCalled();
    const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
    expect(updated!.historyId).toBe('160');
  });

  it('C2: a history with no messagesAdded records behaves the same as no history at all', async () => {
    historyListMock.mockResolvedValue({ data: { history: [{ labelsAdded: [] }], historyId: '161' } });

    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '161' });

    expect(messagesGetMock).not.toHaveBeenCalled();
  });

  // --- D. Gmail API failures ---

  it('D1: an expired/invalid historyId (404) is handled without throwing, and adopts the new historyId directly (documented partial behavior)', async () => {
    historyListMock.mockRejectedValue({ code: 404, message: 'HistoryId is invalid' });

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '175' })
    ).resolves.toBeUndefined();

    const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
    expect(updated!.historyId).toBe('175');
    expect(updated!.status).toBe('ACTIVE');
    assertNoSecretLeakage(); // Google's error response must never leak credentials into our logs
  });

  it('D2: a permanently revoked credential (401) marks the integration ERROR and does not throw', async () => {
    historyListMock.mockRejectedValue({ code: 401, message: 'invalid_grant' });

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '180' })
    ).resolves.toBeUndefined();

    const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
    expect(updated!.status).toBe('ERROR');
    assertNoSecretLeakage(); // a revoked-credential error from Google must never leak the dead credential
  });

  it('D3: a transient/unrecognized Gmail API error propagates (so BullMQ retries it) rather than being silently swallowed', async () => {
    historyListMock.mockRejectedValue(new Error('Service Unavailable'));

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '190' })
    ).rejects.toThrow('Service Unavailable');
  });

  it('D4: a message with no raw MIME body is skipped safely, without crashing the sync', async () => {
    historyListMock.mockResolvedValue({ data: { history: [{ messagesAdded: [{ message: { id: 'msgNoRaw' } }] }], historyId: '195' } });
    messagesGetMock.mockResolvedValue({ data: {} }); // no `raw` field

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '195' })
    ).resolves.toBeUndefined();

    const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
    expect(updated!.historyId).toBe('195');
  });

  it('D5: one message failing to fetch does not block the others in the same history batch', async () => {
    const rawContent = `From: a@example.com\r\nTo: ${emailAddressA}\r\nSubject: Survivor\r\n\r\nBody`;
    historyListMock.mockResolvedValue({
      data: {
        history: [{ messagesAdded: [{ message: { id: 'msgFail' } }, { message: { id: 'msgOk' } }] }],
        historyId: '200'
      }
    });
    messagesGetMock.mockImplementation(async ({ id }: { id: string }) => {
      if (id === 'msgFail') throw new Error('transient fetch failure for this one message');
      return { data: { raw: rawEmailBase64Url(rawContent) } };
    });

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '200' })
    ).resolves.toBeUndefined();

    const sha256 = sha256Of(rawContent);
    const emailRow = await prisma.email.findFirst({ where: { sha256, organizationId: orgA } });
    expect(emailRow).not.toBeNull();
    await trackEmail(emailRow!.id);
    createdJobIds.push(`ingest-${emailRow!.id}`);
  });

  // --- E. Duplicate / idempotency ---

  it('E: processing the same message content twice does not create a duplicate Email row or a duplicate ingestion job', async () => {
    const rawContent = `From: dup@example.com\r\nTo: ${emailAddressA}\r\nSubject: Dup\r\n\r\nSame body`;
    historyListMock.mockResolvedValue({ data: { history: [{ messagesAdded: [{ message: { id: 'msgDup' } }] }], historyId: '210' } });
    messagesGetMock.mockResolvedValue({ data: { raw: rawEmailBase64Url(rawContent) } });

    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '210' });
    const sha256 = sha256Of(rawContent);
    const firstRow = await prisma.email.findFirst({ where: { sha256, organizationId: orgA } });
    expect(firstRow).not.toBeNull();
    await trackEmail(firstRow!.id);
    createdJobIds.push(`ingest-${firstRow!.id}`);

    // Re-run the exact same job (simulating a retried/duplicate BullMQ delivery or a
    // repeated history notification for the same message).
    await prisma.integration.update({ where: { id: integrationAId }, data: { historyId: '100' } }); // reset cursor to replay the same window
    historyListMock.mockResolvedValue({ data: { history: [{ messagesAdded: [{ message: { id: 'msgDup' } }] }], historyId: '210' } });
    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '210' });

    const allMatching = await prisma.email.findMany({ where: { sha256, organizationId: orgA } });
    expect(allMatching).toHaveLength(1); // still exactly one — no duplicate created
  });

  // --- Security: organization isolation ---

  it('SEC1: syncing Org A never creates or touches any data under Org B', async () => {
    const rawContent = `From: iso@example.com\r\nTo: ${emailAddressA}\r\nSubject: Isolation\r\n\r\nBody`;
    historyListMock.mockResolvedValue({ data: { history: [{ messagesAdded: [{ message: { id: 'msgIso' } }] }], historyId: '220' } });
    messagesGetMock.mockResolvedValue({ data: { raw: rawEmailBase64Url(rawContent) } });

    const beforeCountB = await prisma.email.count({ where: { organizationId: orgB } });
    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '220' });
    const afterCountB = await prisma.email.count({ where: { organizationId: orgB } });

    expect(afterCountB).toBe(beforeCountB);

    const sha256 = sha256Of(rawContent);
    const row = await prisma.email.findFirst({ where: { sha256, organizationId: orgA } });
    await trackEmail(row!.id);
    createdJobIds.push(`ingest-${row!.id}`);
  });

  it('SEC2: the job payload\'s organizationId is never trusted for persistence — only the integration row\'s real organizationId is used', async () => {
    const rawContent = `From: spoof@example.com\r\nTo: ${emailAddressA}\r\nSubject: Spoof\r\n\r\nBody`;
    historyListMock.mockResolvedValue({ data: { history: [{ messagesAdded: [{ message: { id: 'msgSpoof' } }] }], historyId: '230' } });
    messagesGetMock.mockResolvedValue({ data: { raw: rawEmailBase64Url(rawContent) } });

    // Deliberately mismatched organizationId in the job payload vs. integrationAId's real org.
    await worker.process({ integrationId: integrationAId, organizationId: orgB, emailAddress: emailAddressA, newHistoryId: '230' });

    const sha256 = sha256Of(rawContent);
    const row = await prisma.email.findFirst({ where: { sha256 } });
    expect(row).not.toBeNull();
    expect(row!.organizationId).toBe(orgA); // real integration owner, not the spoofed payload org
    await trackEmail(row!.id);
    createdJobIds.push(`ingest-${row!.id}`);
  });

  it('SEC3: an unknown integrationId throws rather than silently proceeding', async () => {
    await expect(
      worker.process({ integrationId: crypto.randomUUID(), organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '240' })
    ).rejects.toThrow(/not found/);
  });

  it('SEC4: a non-ACTIVE integration is skipped without throwing or calling the Gmail API', async () => {
    await prisma.integration.update({ where: { id: integrationAId }, data: { status: 'DISCONNECTED' } });

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '250' })
    ).resolves.toBeUndefined();

    expect(historyListMock).not.toHaveBeenCalled();
  });

  // --- Security: token handling ---

  it('SEC5: neither the plaintext nor encrypted OAuth token values ever appear in any log call during a full sync', async () => {
    const rawContent = `From: log@example.com\r\nTo: ${emailAddressA}\r\nSubject: LogCheck\r\n\r\nBody`;
    historyListMock.mockResolvedValue({ data: { history: [{ messagesAdded: [{ message: { id: 'msgLog' } }] }], historyId: '260' } });
    messagesGetMock.mockResolvedValue({ data: { raw: rawEmailBase64Url(rawContent) } });

    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '260' });

    const sha256 = sha256Of(rawContent);
    const row = await prisma.email.findFirst({ where: { sha256 } });
    await trackEmail(row!.id);
    createdJobIds.push(`ingest-${row!.id}`);

    const integration = await prisma.integration.findUnique({ where: { id: integrationAId } });
    const allLogCalls = [
      ...(logger.info as ReturnType<typeof vi.fn>).mock.calls,
      ...(logger.warn as ReturnType<typeof vi.fn>).mock.calls,
      ...(logger.error as ReturnType<typeof vi.fn>).mock.calls
    ];
    const serializedLogs = JSON.stringify(allLogCalls);

    expect(serializedLogs).not.toContain('real-access-token-value-A');
    expect(serializedLogs).not.toContain('real-refresh-token-value-A');
    expect(serializedLogs).not.toContain(integration!.accessToken);
    expect(serializedLogs).not.toContain(integration!.refreshToken);
    void logSpy; // referenced for lint (spy installed in beforeEach)
  });

  it('SEC6: the setCredentials call passes the decrypted token values internally, never the encrypted envelope', async () => {
    historyListMock.mockResolvedValue({ data: { history: [], historyId: '270' } });

    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '270' });

    expect(setCredentialsMock).toHaveBeenCalledWith({
      access_token: 'real-access-token-value-A',
      refresh_token: 'real-refresh-token-value-A'
    });
  });

  // --- OAuth token refresh persistence ---

  it('F1: when googleapis emits a refreshed token, the worker re-encrypts and persists it (never plaintext at rest)', async () => {
    historyListMock.mockResolvedValue({ data: { history: [], historyId: '280' } });

    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '280' });

    // Capture the 'tokens' listener the worker registered on this call's OAuth2 client
    // and simulate googleapis firing it mid-request, exactly as it would on a real refresh.
    expect(onTokensMock).toHaveBeenCalled();
    const [eventName, tokensCallback] = onTokensMock.mock.calls[onTokensMock.mock.calls.length - 1];
    expect(eventName).toBe('tokens');

    await tokensCallback({ access_token: 'refreshed-access-token', refresh_token: 'refreshed-refresh-token', expiry_date: Date.now() + 7200_000 });

    const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
    expect(updated!.accessToken).not.toBe('refreshed-access-token'); // never stored plaintext
    expect(updated!.accessToken).not.toContain('refreshed-access-token');
    const { decryptToken } = await import('@ciperscope/config');
    expect(decryptToken(updated!.accessToken, ENCRYPTION_KEY)).toBe('refreshed-access-token');
    expect(decryptToken(updated!.refreshToken, ENCRYPTION_KEY)).toBe('refreshed-refresh-token');
  });

  it('F2: a refresh event without a new refresh_token (access-token-only refresh) leaves the stored refresh token untouched', async () => {
    await prisma.integration.update({
      where: { id: integrationAId },
      data: { refreshToken: encryptToken('real-refresh-token-value-A', ENCRYPTION_KEY) }
    });
    historyListMock.mockResolvedValue({ data: { history: [], historyId: '285' } });

    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '285' });
    const [, tokensCallback] = onTokensMock.mock.calls[onTokensMock.mock.calls.length - 1];
    await tokensCallback({ access_token: 'access-only-refresh' });

    const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
    const { decryptToken } = await import('@ciperscope/config');
    expect(decryptToken(updated!.refreshToken, ENCRYPTION_KEY)).toBe('real-refresh-token-value-A');
  });

  // --- Malformed Gmail responses ---

  it('G1: a messagesAdded entry with no message object at all is skipped safely', async () => {
    historyListMock.mockResolvedValue({ data: { history: [{ messagesAdded: [{}] }], historyId: '290' } });

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '290' })
    ).resolves.toBeUndefined();

    expect(messagesGetMock).not.toHaveBeenCalled();
  });

  it('G2: a messagesAdded entry whose message has no id is skipped safely', async () => {
    historyListMock.mockResolvedValue({ data: { history: [{ messagesAdded: [{ message: {} }] }], historyId: '291' } });

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '291' })
    ).resolves.toBeUndefined();

    expect(messagesGetMock).not.toHaveBeenCalled();
  });

  it('G3: a completely missing history.data.history field is treated as empty, not a crash', async () => {
    historyListMock.mockResolvedValue({ data: { historyId: '292' } }); // no `history` key at all

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '292' })
    ).resolves.toBeUndefined();
  });

  // --- Persistence-layer failure mid-message ---
  //
  // Note: this deliberately fails at the RawEmailStore boundary (a plain,
  // test-owned dependency injected into the worker), not by spying on the
  // live `prisma` singleton — spying on Prisma Client's own methods proved
  // unreliable in practice (its internal call-batching does not survive
  // being wrapped by vi.spyOn's call-through), which is itself useful
  // evidence: it means this failure mode is exercised at the same
  // try/catch the Gmail-API-failure tests (D5) already prove is resilient,
  // without depending on a fragile mocking technique.

  it('H1: a storage-layer failure while persisting one message is caught, logged, and does not stop the batch or throw the job', async () => {
    const rawContent = `From: b@example.com\r\nTo: ${emailAddressA}\r\nSubject: AfterStoreFail\r\n\r\nBody`;
    historyListMock.mockResolvedValue({
      data: {
        history: [{ messagesAdded: [{ message: { id: 'msgStoreFail' } }, { message: { id: 'msgAfterStoreFail' } }] }],
        historyId: '300'
      }
    });
    messagesGetMock.mockImplementation(async ({ id }: { id: string }) => {
      if (id === 'msgStoreFail') return { data: { raw: rawEmailBase64Url(`From: x@example.com\r\nTo: ${emailAddressA}\r\nSubject: WillFailStore\r\n\r\nBody`) } };
      return { data: { raw: rawEmailBase64Url(rawContent) } };
    });

    const putSpy = vi.spyOn(rawEmailStore, 'put').mockRejectedValueOnce(new Error('simulated storage failure'));
    try {
      await expect(
        worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '300' })
      ).resolves.toBeUndefined(); // the job itself does not throw / is not sent to BullMQ retry for this partial failure
    } finally {
      putSpy.mockRestore();
    }

    // The message processed AFTER the simulated storage failure still succeeded.
    const sha256 = sha256Of(rawContent);
    const survivorRow = await prisma.email.findFirst({ where: { sha256, organizationId: orgA } });
    expect(survivorRow).not.toBeNull();
    await trackEmail(survivorRow!.id);
    createdJobIds.push(`ingest-${survivorRow!.id}`);

    // The failed message was never persisted as an Email row at all.
    const failedSha256 = sha256Of(`From: x@example.com\r\nTo: ${emailAddressA}\r\nSubject: WillFailStore\r\n\r\nBody`);
    const failedRow = await prisma.email.findFirst({ where: { sha256: failedSha256, organizationId: orgA } });
    expect(failedRow).toBeNull();

    // Current (documented, not changed) behavior: the cursor still advances to the new
    // historyId even though one message in this batch failed to persist — a real,
    // pre-existing gap (that message will never be retried by a future sync, since the
    // next sync starts from historyId 300). Recorded here as evidence of actual
    // behavior, not as an endorsement — see the final report's "Idempotency findings".
    const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
    expect(updated!.historyId).toBe('300');
  });

  // --- Disconnect/error-state behavior ---

  it('I1: an integration already in ERROR status is also skipped (not just DISCONNECTED), without calling the Gmail API', async () => {
    await prisma.integration.update({ where: { id: integrationAId }, data: { status: 'ERROR' } });

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '310' })
    ).resolves.toBeUndefined();

    expect(historyListMock).not.toHaveBeenCalled();
  });

  // --- Missing/corrupted credentials ---

  it('J1: a corrupted stored token envelope causes process() to throw (propagates to BullMQ retry) rather than silently proceeding', async () => {
    await prisma.integration.update({ where: { id: integrationAId }, data: { accessToken: 'not-a-valid-encrypted-envelope' } });

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '320' })
    ).rejects.toThrow();

    expect(historyListMock).not.toHaveBeenCalled(); // never reaches the Gmail API with a bad credential
  });

  // --- Phase 10B.1: Gmail History API pagination ---

  it('PAG1: single-page regression — no nextPageToken means exactly one history.list call', async () => {
    historyListMock.mockResolvedValue({ data: { history: [], historyId: '400' } });

    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '400' });

    expect(historyListMock).toHaveBeenCalledTimes(1);
    const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
    expect(updated!.historyId).toBe('400');
  });

  it('PAG2: two pages — both fetched, correct pageToken chaining, messages from both pages ingested, cursor from the last page', async () => {
    const rawPage1 = `From: p1@example.com\r\nTo: ${emailAddressA}\r\nSubject: Page1\r\n\r\nBody`;
    const rawPage2 = `From: p2@example.com\r\nTo: ${emailAddressA}\r\nSubject: Page2\r\n\r\nBody`;

    historyListMock.mockResolvedValueOnce({
      data: { history: [{ messagesAdded: [{ message: { id: 'msgPag2A' } }] }], nextPageToken: 'token2', historyId: '410-partial' }
    });
    historyListMock.mockResolvedValueOnce({
      data: { history: [{ messagesAdded: [{ message: { id: 'msgPag2B' } }] }], historyId: '410' }
    });
    messagesGetMock.mockImplementation(async ({ id }: { id: string }) => {
      if (id === 'msgPag2A') return { data: { raw: rawEmailBase64Url(rawPage1) } };
      return { data: { raw: rawEmailBase64Url(rawPage2) } };
    });

    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '410' });

    expect(historyListMock).toHaveBeenCalledTimes(2);
    expect(historyListMock).toHaveBeenNthCalledWith(1, { userId: 'me', startHistoryId: '100', historyTypes: ['messageAdded'], pageToken: undefined });
    expect(historyListMock).toHaveBeenNthCalledWith(2, { userId: 'me', startHistoryId: '100', historyTypes: ['messageAdded'], pageToken: 'token2' });

    const row1 = await prisma.email.findFirst({ where: { sha256: sha256Of(rawPage1), organizationId: orgA } });
    const row2 = await prisma.email.findFirst({ where: { sha256: sha256Of(rawPage2), organizationId: orgA } });
    expect(row1).not.toBeNull();
    expect(row2).not.toBeNull();
    await trackEmail(row1!.id);
    await trackEmail(row2!.id);
    createdJobIds.push(`ingest-${row1!.id}`, `ingest-${row2!.id}`);

    // Cursor is the LAST page's historyId, not the first (partial) page's.
    const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
    expect(updated!.historyId).toBe('410');
  });

  it('PAG3: three-page chain — all three pages fetched exactly once, in order, all messages processed', async () => {
    const raws = [1, 2, 3].map(
      (n) => `From: p${n}@example.com\r\nTo: ${emailAddressA}\r\nSubject: Chain${n}\r\n\r\nBody`
    );

    historyListMock.mockResolvedValueOnce({
      data: { history: [{ messagesAdded: [{ message: { id: 'msgChain1' } }] }], nextPageToken: 'token2', historyId: 'partial-1' }
    });
    historyListMock.mockResolvedValueOnce({
      data: { history: [{ messagesAdded: [{ message: { id: 'msgChain2' } }] }], nextPageToken: 'token3', historyId: 'partial-2' }
    });
    historyListMock.mockResolvedValueOnce({
      data: { history: [{ messagesAdded: [{ message: { id: 'msgChain3' } }] }], historyId: '420' }
    });
    messagesGetMock.mockImplementation(async ({ id }: { id: string }) => {
      const idx = { msgChain1: 0, msgChain2: 1, msgChain3: 2 }[id as 'msgChain1' | 'msgChain2' | 'msgChain3'];
      return { data: { raw: rawEmailBase64Url(raws[idx]) } };
    });

    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '420' });

    expect(historyListMock).toHaveBeenCalledTimes(3);
    expect(historyListMock).toHaveBeenNthCalledWith(1, expect.objectContaining({ pageToken: undefined }));
    expect(historyListMock).toHaveBeenNthCalledWith(2, expect.objectContaining({ pageToken: 'token2' }));
    expect(historyListMock).toHaveBeenNthCalledWith(3, expect.objectContaining({ pageToken: 'token3' }));
    expect(messagesGetMock).toHaveBeenCalledTimes(3);

    for (const raw of raws) {
      const row = await prisma.email.findFirst({ where: { sha256: sha256Of(raw), organizationId: orgA } });
      expect(row).not.toBeNull();
      await trackEmail(row!.id);
      createdJobIds.push(`ingest-${row!.id}`);
    }

    const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
    expect(updated!.historyId).toBe('420');
  });

  it('PAG4: a page-2 fetch failure surfaces, page-1 messages remain ingested, and the cursor does NOT advance', async () => {
    const rawPage1 = `From: fail-p1@example.com\r\nTo: ${emailAddressA}\r\nSubject: SurvivesPageFail\r\n\r\nBody`;

    historyListMock.mockResolvedValueOnce({
      data: { history: [{ messagesAdded: [{ message: { id: 'msgPag4' } }] }], nextPageToken: 'token2', historyId: 'partial' }
    });
    historyListMock.mockRejectedValueOnce(new Error('Gmail API unavailable on page 2'));
    messagesGetMock.mockResolvedValue({ data: { raw: rawEmailBase64Url(rawPage1) } });

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '430' })
    ).rejects.toThrow('Gmail API unavailable on page 2');

    // Page 1's message was already ingested before page 2 failed — not rolled back.
    const row = await prisma.email.findFirst({ where: { sha256: sha256Of(rawPage1), organizationId: orgA } });
    expect(row).not.toBeNull();
    await trackEmail(row!.id);
    createdJobIds.push(`ingest-${row!.id}`);

    // The cursor must NOT have advanced — history from the failed page 2 was never seen.
    const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
    expect(updated!.historyId).toBe('100'); // unchanged from the beforeEach baseline
  });

  it('PAG5: a per-message failure on page 1 does not prevent page 2 from being processed, and the cursor still advances (existing per-message semantics preserved)', async () => {
    const rawPage2 = `From: survivor-p2@example.com\r\nTo: ${emailAddressA}\r\nSubject: SurvivesMessageFail\r\n\r\nBody`;

    historyListMock.mockResolvedValueOnce({
      data: { history: [{ messagesAdded: [{ message: { id: 'msgPag5Fail' } }] }], nextPageToken: 'token2', historyId: 'partial' }
    });
    historyListMock.mockResolvedValueOnce({
      data: { history: [{ messagesAdded: [{ message: { id: 'msgPag5Ok' } }] }], historyId: '440' }
    });
    messagesGetMock.mockImplementation(async ({ id }: { id: string }) => {
      if (id === 'msgPag5Fail') throw new Error('transient fetch failure for this message only');
      return { data: { raw: rawEmailBase64Url(rawPage2) } };
    });

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '440' })
    ).resolves.toBeUndefined();

    const row = await prisma.email.findFirst({ where: { sha256: sha256Of(rawPage2), organizationId: orgA } });
    expect(row).not.toBeNull();
    await trackEmail(row!.id);
    createdJobIds.push(`ingest-${row!.id}`);

    // Per-message failures (unlike page-level failures) still let the cursor advance —
    // this is the existing, unchanged Phase 10B semantics, now proven across pages too.
    const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
    expect(updated!.historyId).toBe('440');
  });

  it('PAG6: an empty page that still carries a nextPageToken is followed to the next page', async () => {
    const rawPage2 = `From: afterempty@example.com\r\nTo: ${emailAddressA}\r\nSubject: AfterEmptyPage\r\n\r\nBody`;

    historyListMock.mockResolvedValueOnce({
      data: { history: [], nextPageToken: 'token2', historyId: 'partial' } // legal: empty page, more remain
    });
    historyListMock.mockResolvedValueOnce({
      data: { history: [{ messagesAdded: [{ message: { id: 'msgPag6' } }] }], historyId: '450' }
    });
    messagesGetMock.mockResolvedValue({ data: { raw: rawEmailBase64Url(rawPage2) } });

    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '450' });

    expect(historyListMock).toHaveBeenCalledTimes(2);
    const row = await prisma.email.findFirst({ where: { sha256: sha256Of(rawPage2), organizationId: orgA } });
    expect(row).not.toBeNull();
    await trackEmail(row!.id);
    createdJobIds.push(`ingest-${row!.id}`);
  });

  it('PAG7: the same Gmail message appearing on two pages is not ingested twice (existing sha256 dedup, not weakened)', async () => {
    const rawContent = `From: dup-across-pages@example.com\r\nTo: ${emailAddressA}\r\nSubject: DupAcrossPages\r\n\r\nBody`;

    historyListMock.mockResolvedValueOnce({
      data: { history: [{ messagesAdded: [{ message: { id: 'msgPag7Dup' } }] }], nextPageToken: 'token2', historyId: 'partial' }
    });
    historyListMock.mockResolvedValueOnce({
      // Same message reported again on page 2 (a real Gmail behavior with overlapping history windows).
      data: { history: [{ messagesAdded: [{ message: { id: 'msgPag7Dup' } }] }], historyId: '460' }
    });
    messagesGetMock.mockResolvedValue({ data: { raw: rawEmailBase64Url(rawContent) } });

    await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '460' });

    const matching = await prisma.email.findMany({ where: { sha256: sha256Of(rawContent), organizationId: orgA } });
    expect(matching).toHaveLength(1);
    await trackEmail(matching[0].id);
    createdJobIds.push(`ingest-${matching[0].id}`);
  });

  it('PAG8: no OAuth token, refresh token, Authorization header, or credential leaks into logs during a multi-page sync, including a page-level failure', async () => {
    historyListMock.mockResolvedValueOnce({
      data: { history: [], nextPageToken: 'token2', historyId: 'partial' }
    });
    historyListMock.mockRejectedValueOnce({ code: 500, message: 'Internal error' });

    await expect(
      worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '470' })
    ).rejects.toBeTruthy();

    assertNoSecretLeakage();
  });
});
