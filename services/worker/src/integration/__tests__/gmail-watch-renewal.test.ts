import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import crypto from 'crypto';
import { prisma } from '@ciperscope/database';
import { env, encryptToken, decryptToken } from '@ciperscope/config';
import { logger } from '@ciperscope/logger';

/**
 * Phase 10G.1 — services/worker/src/integration/gmail-watch-renewal.ts had
 * zero coverage (it didn't exist before this phase; Phase 10G's discovery
 * audit found gmail.users.watch() was only ever called once, at initial
 * OAuth connection, with no renewal anywhere in the repository). This
 * exercises the real GmailWatchRenewalWorker.renewAll() logic against real
 * Postgres, with the external Google API boundary mocked — the same
 * pattern already established by gmail-sync.integration.test.ts.
 */

const watchMock = vi.fn();
const setCredentialsMock = vi.fn();

vi.mock('googleapis', () => {
  return {
    google: {
      auth: {
        OAuth2: vi.fn().mockImplementation(() => ({
          setCredentials: setCredentialsMock
        }))
      },
      gmail: vi.fn().mockImplementation(() => ({
        users: {
          watch: watchMock
        }
      }))
    }
  };
});

const { GmailWatchRenewalWorker } = await import('../gmail-watch-renewal');

const ENCRYPTION_KEY = env.GMAIL_TOKEN_ENCRYPTION_KEY!;

describe('GmailWatchRenewalWorker.renewAll (Integration — real Postgres, mocked Google API)', () => {
  let orgA: string;
  let orgB: string;
  let activeIntegrationId: string;
  let disconnectedIntegrationId: string;
  let errorIntegrationId: string;
  let otherOrgActiveIntegrationId: string;
  let emailAddressActive: string;
  let emailAddressDisconnected: string;
  let emailAddressError: string;
  let emailAddressOtherOrg: string;
  let worker: InstanceType<typeof GmailWatchRenewalWorker>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeAll(async () => {
    if (!ENCRYPTION_KEY) {
      throw new Error('GMAIL_TOKEN_ENCRYPTION_KEY must be set to run this test suite (see .env.example)');
    }
    if (!env.GOOGLE_PUBSUB_TOPIC) {
      throw new Error('GOOGLE_PUBSUB_TOPIC must be set to run this test suite (see .env.example)');
    }

    worker = new GmailWatchRenewalWorker();

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    emailAddressActive = `watch-renewal-active-${crypto.randomUUID()}@example.com`;
    emailAddressDisconnected = `watch-renewal-disc-${crypto.randomUUID()}@example.com`;
    emailAddressError = `watch-renewal-error-${crypto.randomUUID()}@example.com`;
    emailAddressOtherOrg = `watch-renewal-other-org-${crypto.randomUUID()}@example.com`;

    await prisma.organization.createMany({
      data: [
        { id: orgA, name: 'Watch Renewal Test Org A' },
        { id: orgB, name: 'Watch Renewal Test Org B' }
      ]
    });

    const active = await prisma.integration.create({
      data: {
        organizationId: orgA,
        provider: 'GMAIL',
        emailAddress: emailAddressActive,
        accessToken: encryptToken('active-org-a-access-token', ENCRYPTION_KEY),
        refreshToken: encryptToken('active-org-a-refresh-token', ENCRYPTION_KEY),
        expiresAt: new Date(Date.now() + 3600_000),
        historyId: '100',
        status: 'ACTIVE'
      }
    });
    activeIntegrationId = active.id;

    const disconnected = await prisma.integration.create({
      data: {
        organizationId: orgA,
        provider: 'GMAIL',
        emailAddress: emailAddressDisconnected,
        accessToken: encryptToken('', ENCRYPTION_KEY),
        refreshToken: encryptToken('', ENCRYPTION_KEY),
        expiresAt: new Date(Date.now() + 3600_000),
        historyId: '200',
        status: 'DISCONNECTED'
      }
    });
    disconnectedIntegrationId = disconnected.id;

    const errored = await prisma.integration.create({
      data: {
        organizationId: orgA,
        provider: 'GMAIL',
        emailAddress: emailAddressError,
        accessToken: encryptToken('error-org-a-access-token', ENCRYPTION_KEY),
        refreshToken: encryptToken('error-org-a-refresh-token', ENCRYPTION_KEY),
        expiresAt: new Date(Date.now() + 3600_000),
        historyId: '300',
        status: 'ERROR'
      }
    });
    errorIntegrationId = errored.id;

    const otherOrgActive = await prisma.integration.create({
      data: {
        organizationId: orgB,
        provider: 'GMAIL',
        emailAddress: emailAddressOtherOrg,
        accessToken: encryptToken('active-org-b-access-token', ENCRYPTION_KEY),
        refreshToken: encryptToken('active-org-b-refresh-token', ENCRYPTION_KEY),
        expiresAt: new Date(Date.now() + 3600_000),
        historyId: '400',
        status: 'ACTIVE'
      }
    });
    otherOrgActiveIntegrationId = otherOrgActive.id;
  });

  afterAll(async () => {
    await prisma.integration.deleteMany({
      where: { id: { in: [activeIntegrationId, disconnectedIntegrationId, errorIntegrationId, otherOrgActiveIntegrationId] } }
    });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
  });

  beforeEach(() => {
    vi.clearAllMocks();
    watchMock.mockResolvedValue({ data: { historyId: '999', expiration: String(Date.now() + 7 * 24 * 60 * 60 * 1000) } });
    logSpy = vi.spyOn(logger, 'info');
    vi.spyOn(logger, 'warn');
    vi.spyOn(logger, 'error');
  });

  function allLoggedText(): string {
    return JSON.stringify([
      ...(logger.info as ReturnType<typeof vi.fn>).mock.calls,
      ...(logger.warn as ReturnType<typeof vi.fn>).mock.calls,
      ...(logger.error as ReturnType<typeof vi.fn>).mock.calls
    ]);
  }

  it('renews watch() for every ACTIVE Gmail integration, across all organizations', async () => {
    const result = await worker.renewAll();

    expect(watchMock).toHaveBeenCalledTimes(2); // activeIntegrationId + otherOrgActiveIntegrationId only
    expect(result.renewed).toBe(2);
    expect(result.failed).toBe(0);
    void logSpy;
  });

  it('does NOT call watch() for a DISCONNECTED integration', async () => {
    await worker.renewAll();

    const calledOrgIds = watchMock.mock.calls.length;
    expect(calledOrgIds).toBe(2); // never 3 — the DISCONNECTED row is excluded by the query itself
    // Directly prove the DISCONNECTED row's own credentials were never touched/read into a client.
    const setCredentialsCalls = setCredentialsMock.mock.calls.map((c) => c[0]);
    expect(setCredentialsCalls.some((c) => c.access_token === '')).toBe(false);
  });

  it('does NOT call watch() for an ERROR integration, and does not flip it back to ACTIVE', async () => {
    await worker.renewAll();

    const errored = await prisma.integration.findUnique({ where: { id: errorIntegrationId } });
    expect(errored!.status).toBe('ERROR'); // unchanged — renewal never touches non-ACTIVE rows
    expect(decryptToken(errored!.accessToken, ENCRYPTION_KEY)).toBe('error-org-a-access-token'); // untouched
  });

  it('a Gmail watch() API failure for one integration does not change its status or credentials, and does not block the others', async () => {
    watchMock.mockImplementation(async (params: { userId: string }) => {
      void params;
      // Fail exactly once for the first call in this run, succeed for the rest —
      // deterministic via call-count, not timing.
      if (watchMock.mock.calls.length === 1) {
        const err: { code: number; message: string } = { code: 401, message: 'invalid_grant' };
        throw err;
      }
      return { data: { historyId: '999', expiration: String(Date.now() + 7 * 24 * 60 * 60 * 1000) } };
    });

    const result = await worker.renewAll();

    expect(result.renewed).toBe(1);
    expect(result.failed).toBe(1);

    // THE INVARIANT: a renewal failure must not destroy credentials or
    // change status — GmailSyncWorker's own CAS-protected 401 handler is
    // the single source of truth for that transition, not this file.
    const stillActive = await prisma.integration.findUnique({ where: { id: activeIntegrationId } });
    expect(stillActive!.status).toBe('ACTIVE');
    const otherOrgStillActive = await prisma.integration.findUnique({ where: { id: otherOrgActiveIntegrationId } });
    expect(otherOrgStillActive!.status).toBe('ACTIVE');
  });

  it('running renewAll() multiple times is idempotent — no destructive overwrite of credentials across repeated runs', async () => {
    await worker.renewAll();
    await worker.renewAll();
    const result = await worker.renewAll();

    expect(result.renewed).toBe(2);
    expect(result.failed).toBe(0);

    const active = await prisma.integration.findUnique({ where: { id: activeIntegrationId } });
    expect(decryptToken(active!.accessToken, ENCRYPTION_KEY)).toBe('active-org-a-access-token'); // unchanged across 3 runs
    expect(decryptToken(active!.refreshToken, ENCRYPTION_KEY)).toBe('active-org-a-refresh-token');
    expect(active!.historyId).toBe('100'); // untouched by this file, per its own invariant
  });

  it('each integration\'s own credentials are used for its own watch() call — never mixed across organizations/integrations', async () => {
    await worker.renewAll();

    const setCredentialsCalls = setCredentialsMock.mock.calls.map((c) => c[0]);
    const accessTokensUsed = setCredentialsCalls.map((c) => c.access_token).sort();
    expect(accessTokensUsed).toEqual(['active-org-a-access-token', 'active-org-b-access-token'].sort());

    const refreshTokensUsed = setCredentialsCalls.map((c) => c.refresh_token).sort();
    expect(refreshTokensUsed).toEqual(['active-org-a-refresh-token', 'active-org-b-refresh-token'].sort());
  });

  it('existing integration credentials remain intact regardless of renewal outcome', async () => {
    watchMock.mockRejectedValue({ code: 500, message: 'Internal error' });

    await worker.renewAll();

    const active = await prisma.integration.findUnique({ where: { id: activeIntegrationId } });
    expect(decryptToken(active!.accessToken, ENCRYPTION_KEY)).toBe('active-org-a-access-token');
    expect(decryptToken(active!.refreshToken, ENCRYPTION_KEY)).toBe('active-org-a-refresh-token');
    expect(active!.status).toBe('ACTIVE');
  });

  it('no OAuth token, refresh token, or Authorization header value ever appears in logs, including on a failure path', async () => {
    watchMock.mockImplementation(async () => {
      const err: { code: number; message: string; response: { data: { error: string; authorization: string } } } = {
        code: 401,
        message: 'invalid_grant',
        response: { data: { error: 'invalid_grant', authorization: 'Bearer secret-watch-renewal-token' } }
      };
      throw err;
    });

    await worker.renewAll();

    const logged = allLoggedText();
    expect(logged).not.toContain('active-org-a-access-token');
    expect(logged).not.toContain('active-org-a-refresh-token');
    expect(logged).not.toContain('active-org-b-access-token');
    expect(logged).not.toContain('active-org-b-refresh-token');
    expect(logged).not.toContain('secret-watch-renewal-token');
    expect(logged).not.toMatch(/Bearer\s+\S/i);
  });
});
