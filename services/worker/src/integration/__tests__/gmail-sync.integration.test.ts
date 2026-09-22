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

  // --- OAuth token refresh compare-and-swap (Phase 10D.2) ---
  //
  // OAUTH1 (normal refresh persists accessToken) and OAUTH2/OAUTH3 (a new
  // refresh_token persists; an omitted one is preserved) are already fully
  // covered by F1 and F2 above — not duplicated here. This section covers
  // what F1/F2 do not: the concurrent-write race and its fix.

  describe('OAuth token refresh — compare-and-swap', () => {
    it('OAUTH4: a stale token-refresh write (registered before a concurrent execution\'s refresh) cannot overwrite the newer, already-persisted token state', async () => {
      historyListMock.mockResolvedValue({ data: { history: [], historyId: '290' } });

      // Two concurrent executions for the SAME integration each build their
      // own OAuth2Client and register their own 'tokens' listener — captured
      // here as two independent closures, exactly as googleapis would invoke
      // them on two real concurrent GmailSyncWorker.process() calls.
      await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '290' });
      const [, executionA] = onTokensMock.mock.calls[onTokensMock.mock.calls.length - 1];

      await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '290' });
      const [, executionB] = onTokensMock.mock.calls[onTokensMock.mock.calls.length - 1];

      // Deterministic ordering (no setTimeout): B's refresh — the one that
      // will end up "newer" — is applied first.
      await executionB({ access_token: 'execution-B-newer-access-token', expiry_date: Date.now() + 7200_000 });

      const afterB = await prisma.integration.findUnique({ where: { id: integrationAId } });
      const { decryptToken } = await import('@ciperscope/config');
      expect(decryptToken(afterB!.accessToken, ENCRYPTION_KEY)).toBe('execution-B-newer-access-token');

      // A's refresh — captured BEFORE B's, representing the execution that
      // started first but resolves/writes second with now-stale data — is
      // applied second. Pre-fix, this unconditionally overwrote B's value.
      await executionA({ access_token: 'execution-A-stale-access-token', expiry_date: Date.now() + 3600_000 });

      const finalState = await prisma.integration.findUnique({ where: { id: integrationAId } });
      // THE FIX: A's stale write must NOT have landed — B's value survives.
      expect(decryptToken(finalState!.accessToken, ENCRYPTION_KEY)).toBe('execution-B-newer-access-token');
      expect(allLoggedText()).toMatch(/another concurrent execution already updated the stored credentials/i);
    });

    it('OAUTH5: the token-refresh compare-and-swap never touches historyId — the Phase 10D.1 cursor CAS is unaffected', async () => {
      historyListMock.mockResolvedValue({ data: { history: [], historyId: '295' } });
      await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '295' });

      const afterSync = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(afterSync!.historyId).toBe('295'); // the sync's own cursor CAS succeeded normally

      const [, tokensCallback] = onTokensMock.mock.calls[onTokensMock.mock.calls.length - 1];
      await tokensCallback({ access_token: 'oauth5-refresh-token-value' });

      const afterRefresh = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(afterRefresh!.historyId).toBe('295'); // unchanged by the token-refresh write
    });

    it('OAUTH6: no accessToken, refreshToken, or Authorization value appears in logs, including on a CAS-loss (concurrent refresh) path', async () => {
      historyListMock.mockResolvedValue({ data: { history: [], historyId: '300' } });

      await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '300' });
      const [, executionA] = onTokensMock.mock.calls[onTokensMock.mock.calls.length - 1];

      await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '300' });
      const [, executionB] = onTokensMock.mock.calls[onTokensMock.mock.calls.length - 1];

      await executionB({ access_token: 'secret-oauth6-newer-token' });
      await executionA({ access_token: 'secret-oauth6-stale-token' }); // triggers the CAS-loss log line

      assertNoSecretLeakage();
      expect(allLoggedText()).not.toContain('secret-oauth6-newer-token');
      expect(allLoggedText()).not.toContain('secret-oauth6-stale-token');
    });
  });

  // --- 404 / invalid-historyId recovery compare-and-swap (Phase 10E.1) ---
  //
  // Phase 10E's discovery audit built a temporary (deleted-after-use) live
  // reproduction proving that the 404-recovery branch's then-unconditional
  // historyId write could silently overwrite an already-newer, already-CAS-
  // protected cursor committed by a concurrent execution. This section is
  // the permanent regression coverage for the fix.
  //
  // 404-CAS-2 (no concurrent change -> CAS succeeds) and 404-CAS-4 (CAS-loss
  // path never throws) are already fully exercised by the pre-existing D1
  // test above — not duplicated in substance here, only named explicitly
  // below for traceability against the acceptance criteria.

  describe('404 / invalid-historyId recovery — compare-and-swap', () => {
    it('404-CAS-1: another execution advances historyId to 999 before this execution\'s 404 recovery write attempts to land — the CAS affects 0 rows and 999 survives', async () => {
      await prisma.integration.update({ where: { id: integrationAId }, data: { historyId: '150' } });

      // Deterministic ordering, no timing: the concurrent change is performed
      // as a side effect of the mocked history.list call itself, placing it
      // exactly between this execution's read (process() entry, historyId=150)
      // and its own 404-recovery CAS write.
      historyListMock.mockImplementation(async () => {
        await prisma.integration.update({ where: { id: integrationAId }, data: { historyId: '999' } });
        const err: { code: number; message: string } = { code: 404, message: 'HistoryId is invalid' };
        throw err;
      });

      await expect(
        worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '175' })
      ).resolves.toBeUndefined(); // CAS loss is not a thrown/fatal error

      const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(updated!.historyId).toBe('999'); // the concurrently-set newer value survives, untouched by the stale '175' recovery attempt
      expect(allLoggedText()).toMatch(/historyId recovery not persisted: another concurrent execution already changed the cursor/i);
    });

    it('404-CAS-2 (named for traceability): no concurrent change — the 404 recovery CAS succeeds and persists the recovery historyId (see pre-existing D1 above for full coverage)', async () => {
      historyListMock.mockRejectedValue({ code: 404, message: 'HistoryId is invalid' });

      await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '180' });

      const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(updated!.historyId).toBe('180');
    });

    it('404-CAS-3: original historyId is null, and another process sets a real value before this execution\'s recovery CAS attempts to land — the newer value survives', async () => {
      await prisma.integration.update({ where: { id: integrationAId }, data: { historyId: null } });

      historyListMock.mockImplementation(async () => {
        // Simulates a different, concurrently-running execution completing a
        // normal first-ever sync (moving the cursor from null to a real
        // value) while this execution is still in flight with its own
        // original snapshot of null.
        await prisma.integration.update({ where: { id: integrationAId }, data: { historyId: '999' } });
        const err: { code: number; message: string } = { code: 404, message: 'HistoryId is invalid' };
        throw err;
      });

      await expect(
        worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '175' })
      ).resolves.toBeUndefined();

      const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(updated!.historyId).toBe('999'); // never overwritten back by the null-originated stale recovery attempt
      expect(allLoggedText()).toMatch(/historyId recovery not persisted: another concurrent execution already changed the cursor/i);
    });

    it('404-CAS-4 (named for traceability): a CAS loss on the recovery path does not throw and does not fail the job (see pre-existing D1 above for the base 404 case)', async () => {
      await prisma.integration.update({ where: { id: integrationAId }, data: { historyId: '150' } });
      historyListMock.mockImplementation(async () => {
        await prisma.integration.update({ where: { id: integrationAId }, data: { historyId: '999' } });
        const err: { code: number; message: string } = { code: 404, message: 'HistoryId is invalid' };
        throw err;
      });

      // The promise must resolve (job succeeds), never reject — a CAS loss
      // here is an expected concurrency outcome, not a processing failure.
      await expect(
        worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '175' })
      ).resolves.toBeUndefined();
    });

    it('404-CAS-5: the CAS-loss log line contains no OAuth token, Authorization header, raw MIME, or other secret', async () => {
      await prisma.integration.update({ where: { id: integrationAId }, data: { historyId: '150' } });
      historyListMock.mockImplementation(async () => {
        await prisma.integration.update({ where: { id: integrationAId }, data: { historyId: '999' } });
        const err: { code: number; message: string } = { code: 404, message: 'HistoryId is invalid' };
        throw err;
      });

      await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '175' });

      assertNoSecretLeakage();
    });
  });

  // --- 401/invalid_grant status compare-and-swap (Phase 10F.1) ---
  //
  // Phase 10F's discovery audit identified a genuine cross-path write-write
  // race: a stale in-flight sync execution's unconditional
  // Integration.status = 'ERROR' write can overwrite a newer, deliberate
  // status='DISCONNECTED' committed by the real disconnect endpoint
  // (services/api/src/modules/integration/integration.routes.ts) while the
  // sync was still in flight. This section is the permanent regression
  // coverage for the fix. Note: the disconnect endpoint clears credentials
  // to an encrypted EMPTY STRING (accessToken/refreshToken are non-nullable
  // columns), not literal null — assertions below match that real behavior.
  //
  // STATUS-CAS-2 (no concurrent change -> ERROR persists, no throw) is
  // already fully exercised by the pre-existing D2 test above — not
  // duplicated in substance here, only named explicitly for traceability.

  describe('401/invalid_grant — status compare-and-swap', () => {
    it('STATUS-CAS-1: the exact reproduced race — worker reads ACTIVE, pauses, a real disconnect commits DISCONNECTED, worker resumes and hits invalid_grant — final status MUST remain DISCONNECTED, never ERROR', async () => {
      // Deterministic promise barrier — never setTimeout/arbitrary delay.
      let releaseGate!: () => void;
      const gate = new Promise<void>((resolve) => { releaseGate = resolve; });
      let reachedGate = false;

      historyListMock.mockImplementation(async () => {
        // The worker has already passed the `status !== 'ACTIVE'` guard at
        // process() entry (it read ACTIVE) and is now blocked here — i.e.
        // "paused immediately before the invalid_grant/status-write path",
        // exactly as specified.
        reachedGate = true;
        await gate;
        const err: { code: number; message: string } = { code: 401, message: 'invalid_grant' };
        throw err;
      });

      const workerPromise = worker.process({
        integrationId: integrationAId,
        organizationId: orgA,
        emailAddress: emailAddressA,
        newHistoryId: '999'
      });

      // Poll (not sleep-and-hope) until the worker has genuinely reached the
      // gate — guarantees its ACTIVE read already happened before disconnect.
      const deadline = Date.now() + 5000;
      while (!reachedGate) {
        if (Date.now() > deadline) throw new Error('Worker never reached the gate — test setup error');
        await new Promise((r) => setTimeout(r, 5));
      }

      // Represents the real disconnect operation committing while the sync
      // is still in flight — same field writes as the actual disconnect
      // endpoint (status + both credential fields cleared).
      await prisma.integration.update({
        where: { id: integrationAId },
        data: {
          status: 'DISCONNECTED',
          accessToken: encryptToken('', ENCRYPTION_KEY),
          refreshToken: encryptToken('', ENCRYPTION_KEY)
        }
      });

      // Release the worker — it now hits the invalid_grant branch and
      // attempts its CAS write.
      releaseGate();
      await expect(workerPromise).resolves.toBeUndefined(); // completes normally, no throw

      const finalState = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(finalState!.status).toBe('DISCONNECTED'); // THE FIX: never overwritten to ERROR
      const { decryptToken } = await import('@ciperscope/config');
      expect(decryptToken(finalState!.accessToken, ENCRYPTION_KEY)).toBe(''); // disconnect's clearing survives, untouched
      expect(decryptToken(finalState!.refreshToken, ENCRYPTION_KEY)).toBe('');
      expect(allLoggedText()).toMatch(/ERROR status not persisted: integration already changed state/i);
    }, 15000);

    it('STATUS-CAS-2 (named for traceability): no concurrent change — the CAS succeeds and ERROR persists, worker does not throw (see pre-existing D2 above for full coverage)', async () => {
      historyListMock.mockRejectedValue({ code: 401, message: 'invalid_grant' });

      await expect(
        worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '190' })
      ).resolves.toBeUndefined();

      const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(updated!.status).toBe('ERROR');
    });

    it('STATUS-CAS-3: status changed to DISCONNECTED before the worker\'s own status write attempts to land — the CAS loses, no throw, DISCONNECTED survives', async () => {
      historyListMock.mockImplementation(async () => {
        await prisma.integration.update({ where: { id: integrationAId }, data: { status: 'DISCONNECTED' } });
        const err: { code: number; message: string } = { code: 401, message: 'invalid_grant' };
        throw err;
      });

      await expect(
        worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '195' })
      ).resolves.toBeUndefined(); // CAS loss is not a thrown/fatal error

      const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(updated!.status).toBe('DISCONNECTED');
    });

    it('STATUS-CAS-4: the status CAS touches only status — historyId, accessToken, and refreshToken are untouched by this branch', async () => {
      await prisma.integration.update({ where: { id: integrationAId }, data: { historyId: '500' } });
      const beforeAccessToken = (await prisma.integration.findUnique({ where: { id: integrationAId } }))!.accessToken;
      const beforeRefreshToken = (await prisma.integration.findUnique({ where: { id: integrationAId } }))!.refreshToken;

      historyListMock.mockRejectedValue({ code: 401, message: 'invalid_grant' });
      await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '505' });

      const updated = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(updated!.status).toBe('ERROR'); // the field this branch DOES change
      expect(updated!.historyId).toBe('500'); // unchanged
      expect(updated!.accessToken).toBe(beforeAccessToken); // unchanged
      expect(updated!.refreshToken).toBe(beforeRefreshToken); // unchanged
    });

    it('STATUS-CAS-5: the CAS-loss path never logs OAuth tokens, Authorization headers, or MIME content', async () => {
      historyListMock.mockImplementation(async () => {
        await prisma.integration.update({ where: { id: integrationAId }, data: { status: 'DISCONNECTED' } });
        // Representative secret values planted in the error itself, the way
        // a real Google API error object might carry request/response
        // context — proves the logger call never forwards the raw error's
        // content, only the safe, fixed message + integrationId.
        const err = {
          code: 401,
          message: 'invalid_grant',
          response: { data: { error: 'invalid_grant', authorization: 'Bearer secret-status-cas5-token' } }
        };
        throw err;
      });

      await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '199' });

      assertNoSecretLeakage();
      expect(allLoggedText()).not.toContain('secret-status-cas5-token');
      expect(allLoggedText()).not.toMatch(/Bearer\s+\S/i);
    });
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

  // --- CAS: compare-and-swap cursor persistence (Phase 10D.1) ---
  //
  // Phase 10D empirically reproduced a cursor-regression race (a temporary,
  // deterministic-barrier harness — deleted after that discovery phase, not
  // committed) against real Postgres: two concurrent GmailSyncWorker.process()
  // calls for the same Integration, where the slower execution's unconditional
  // final `Integration.update` overwrote an already-newer, already-committed
  // historyId. This section is the permanent regression coverage for the
  // compare-and-swap fix that closes that race.

  describe('CAS — compare-and-swap cursor persistence', () => {
    it('CAS1: the exact reproduced race — A reads 100 and pauses, B reads 100 and commits 120, A resumes and attempts 110 — final historyId MUST remain 120, not regress', async () => {
      // Deterministic promise gate — never setTimeout/arbitrary delay.
      let releaseGate!: () => void;
      const gate = new Promise<void>((resolve) => { releaseGate = resolve; });
      let phase: 'A-blocked' | 'B-active' = 'A-blocked';
      let aReachedGate = false;

      historyListMock.mockImplementation(async () => {
        if (phase === 'A-blocked') {
          aReachedGate = true;
          await gate; // Worker A blocks here — its Gmail call has "read" historyId=100
          // (via the do-while loop's startHistoryId: integration.historyId snapshot
          // taken at process() entry) and is paused before it can reach its own
          // final cursor write, exactly as the acceptance criteria specifies.
          return { data: { history: [], historyId: '110' } };
        }
        // Worker B: fast, completes, commits historyId=120.
        return { data: { history: [], historyId: '120' } };
      });

      // 1. Start Worker A — it calls history.list, hits the gate, blocks.
      const aPromise = worker.process({
        integrationId: integrationAId,
        organizationId: orgA,
        emailAddress: emailAddressA,
        newHistoryId: '999'
      });

      // 2. Poll (not sleep-and-hope) until A has genuinely reached the gate —
      //    guarantees A's read of historyId=100 already happened before B starts.
      const deadline = Date.now() + 5000;
      while (!aReachedGate) {
        if (Date.now() > deadline) throw new Error('Worker A never reached the gate — test setup error');
        await new Promise((r) => setTimeout(r, 5));
      }

      // 3. Run Worker B to full completion — reads historyId=100 (same as A),
      //    commits historyId=120.
      phase = 'B-active';
      await worker.process({
        integrationId: integrationAId,
        organizationId: orgA,
        emailAddress: emailAddressA,
        newHistoryId: '120'
      });

      const afterB = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(afterB?.historyId).toBe('120'); // sanity check: B's write landed

      // 4. Release Worker A. Its own CAS write (`WHERE historyId = '100'`) must
      //    now affect zero rows, since the stored value is '120', not '100'.
      releaseGate();
      await expect(aPromise).resolves.toBeUndefined(); // CAS loss is NOT a thrown error

      const finalState = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(finalState?.historyId).toBe('120'); // THE FIX: no regression to '110'

      // A safe, generic concurrency log line was emitted — no secrets.
      expect(allLoggedText()).toMatch(/another concurrent execution already advanced it/i);
      assertNoSecretLeakage();
    }, 15000);

    it('CAS2: normal single-worker execution still advances the cursor via the CAS write (no concurrent contender)', async () => {
      historyListMock.mockResolvedValue({ data: { history: [], historyId: '160' } });

      await worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '160' });

      const integration = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(integration?.historyId).toBe('160');
      // No "another concurrent execution" line — the CAS succeeded on the first attempt.
      expect(allLoggedText()).not.toMatch(/another concurrent execution already advanced it/i);
    });

    it('CAS3: a cursor change that happens between this execution\'s read and its write causes the CAS to lose without overwriting the newer value, and without throwing', async () => {
      // Single-execution simulation of "another worker already advanced the
      // cursor concurrently": the mocked history.list call itself performs the
      // concurrent write as a side effect, deterministically placing the race
      // exactly between this execution's initial read (at process() entry) and
      // its own final CAS write.
      historyListMock.mockImplementation(async () => {
        await prisma.integration.update({ where: { id: integrationAId }, data: { historyId: '777' } });
        return { data: { history: [], historyId: '130' } }; // this execution's own (now-stale) candidate value
      });

      await expect(
        worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '130' })
      ).resolves.toBeUndefined(); // CAS loss is an expected outcome, never a thrown/fatal error

      const integration = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(integration?.historyId).toBe('777'); // the concurrently-set newer value survives, untouched

      expect(allLoggedText()).toMatch(/another concurrent execution already advanced it/i);
      assertNoSecretLeakage(); // no token/Authorization/MIME content in the concurrency log line
    });

    it('CAS4: a page-level failure still prevents the cursor from advancing at all (CAS write is never reached)', async () => {
      historyListMock.mockRejectedValueOnce({ code: 500, message: 'Internal error' });

      await expect(
        worker.process({ integrationId: integrationAId, organizationId: orgA, emailAddress: emailAddressA, newHistoryId: '999' })
      ).rejects.toBeTruthy();

      const integration = await prisma.integration.findUnique({ where: { id: integrationAId } });
      expect(integration?.historyId).toBe('100'); // unchanged — same as pre-CAS behavior (see PAG4)
    });
  });
});
