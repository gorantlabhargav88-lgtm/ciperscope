import { google } from 'googleapis';
import { prisma } from '@ciperscope/database';
import { env, decryptToken, encryptToken, requireGmailTokenEncryptionKey } from '@ciperscope/config';
import { logger, generateRequestId } from '@ciperscope/logger';
import { RawEmailStore } from '@ciperscope/storage';
import {
  createRedisConnection,
  ensureEmailOutboxEvent,
  EmailProcessingStage,
  publishNotification,
} from '@ciperscope/queue';
import IORedis from 'ioredis';
import crypto from 'crypto';
import { Readable } from 'node:stream';

export interface GmailSyncJobPayload {
  integrationId: string;
  organizationId: string;
  emailAddress: string;
  newHistoryId: string;
}

// Shape of the Gaxios/Google API error thrown by googleapis calls, limited to
// the fields this worker actually reads (googleapis re-exports gaxios errors
// without a first-class type for them).
interface GoogleApiError {
  code?: number;
  message?: string;
  response?: { data?: { error?: string } };
}

export class GmailSyncWorker {
  private notificationRedis: IORedis;

  constructor(private rawEmailStore: RawEmailStore) {
    // A dedicated connection, created once here (GmailSyncWorker itself is
    // instantiated once at worker startup, never per-job — see
    // services/worker/src/index.ts) — same self-contained pattern this
    // class already uses for its own QueueManager above, rather than
    // threading a shared connection through from index.ts.
    this.notificationRedis = createRedisConnection(env.REDIS_URL);
  }

  async process(jobData: GmailSyncJobPayload) {
    const { integrationId, newHistoryId } = jobData;

    const integration = await prisma.integration.findUnique({
      where: { id: integrationId }
    });

    if (!integration) {
      throw new Error(`Integration ${integrationId} not found`);
    }

    // Snapshot the cursor value this execution is about to act on. Used as
    // the compare-and-swap guard when persisting the final cursor below —
    // see the comment at that write for why an unconditional update is
    // unsafe under concurrent execution (Phase 10D empirically reproduced a
    // regression without it).
    const originalHistoryId = integration.historyId;

    if (integration.status !== 'ACTIVE') {
      logger.warn({ integrationId, status: integration.status }, 'Skipping sync for a non-active Gmail connection');
      return;
    }

    const encryptionKey = requireGmailTokenEncryptionKey();

    const oauth2Client = new google.auth.OAuth2(
      env.GOOGLE_CLIENT_ID,
      env.GOOGLE_CLIENT_SECRET,
      env.GOOGLE_OAUTH_REDIRECT_URI
    );

    oauth2Client.setCredentials({
      access_token: decryptToken(integration.accessToken, encryptionKey),
      refresh_token: decryptToken(integration.refreshToken, encryptionKey)
    });

    // Tracks the encrypted accessToken value this execution last confirmed is
    // actually stored — starts at what was read above, and is advanced after
    // each successful write below. Used as the compare-and-swap guard on the
    // token-refresh update (Phase 10D.2): two concurrent executions for the
    // same Integration each build their own OAuth2Client and can each
    // independently trigger their own refresh, so an unconditional update
    // here has the same last-write-wins shape already fixed for historyId in
    // Phase 10D.1. Guarding on the actual current accessToken (not a token
    // string comparison, not a lexical/numeric ordering — there is no
    // ordering relation between opaque OAuth tokens) means a write only
    // lands if nothing else has changed the stored credentials since this
    // execution last observed them; a second refresh within the SAME
    // execution (Google's client can fire 'tokens' more than once per
    // instance) still succeeds because the tracked value advances on success.
    let lastKnownAccessToken = integration.accessToken;

    oauth2Client.on('tokens', async (tokens) => {
      const nextAccessToken = encryptToken(tokens.access_token!, encryptionKey);
      const updateResult = await prisma.integration.updateMany({
        where: { id: integrationId, accessToken: lastKnownAccessToken },
        data: {
          accessToken: nextAccessToken,
          ...(tokens.refresh_token ? { refreshToken: encryptToken(tokens.refresh_token, encryptionKey) } : {}),
          ...(tokens.expiry_date ? { expiresAt: new Date(tokens.expiry_date) } : {})
        }
      });

      if (updateResult.count === 0) {
        // No token, header, or credential content is logged here — only the
        // integrationId and a generic description, matching this file's
        // existing logging convention.
        logger.info(
          { integrationId },
          'Gmail OAuth token refresh not persisted: another concurrent execution already updated the stored credentials'
        );
        return;
      }

      lastKnownAccessToken = nextAccessToken;
    });

    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    // Gmail's history.list is paginated: a busy mailbox can have more history
    // records than fit on one page. Per Google's own documented contract,
    // "If you receive no nextPageToken in the response, there are no updates
    // to retrieve and you can store the returned historyId for a future
    // request" — so the cursor is only ever known-safe to persist once every
    // page has been fetched AND processed. Fetching a page that throws is a
    // page-level failure: it must propagate (so BullMQ can retry the whole
    // job) rather than silently leaving later, unprocessed history behind a
    // cursor that already claims to be caught up.
    let pageToken: string | undefined = undefined;
    let latestHistoryId: string | null | undefined;

    do {
      let historyResponse;
      try {
        historyResponse = await gmail.users.history.list({
          userId: 'me',
          startHistoryId: integration.historyId || undefined,
          historyTypes: ['messageAdded'],
          pageToken
        });
      } catch (error: unknown) {
        const gmailError = error as GoogleApiError;
        if (gmailError.code === 404 || (gmailError.message && gmailError.message.includes('HistoryId is invalid'))) {
          logger.warn({ integrationId }, 'History ID expired or invalid, performing full sync (not fully implemented) - updating to new historyId');
          // Same compare-and-swap shape as the success-path cursor write
          // below (Phase 10D.1) and for the same reason (Phase 10E proved
          // this exact regression live, against real Postgres): a concurrent
          // execution for the same Integration may have already advanced the
          // cursor past originalHistoryId while this execution was in
          // flight. Guarding on `historyId: originalHistoryId` means this
          // recovery write only lands if nothing else has changed the
          // cursor since this execution read it; if it has, this execution's
          // own (potentially stale) recovery value is discarded rather than
          // overwriting whatever the other execution already committed.
          const recoveryUpdateResult = await prisma.integration.updateMany({
            where: { id: integrationId, historyId: originalHistoryId },
            data: { historyId: newHistoryId }
          });

          if (recoveryUpdateResult.count === 0) {
            // No token, header, or MIME content is logged here — only the
            // integrationId and a generic description, matching this file's
            // existing logging convention.
            logger.info(
              { integrationId },
              'Gmail sync historyId recovery not persisted: another concurrent execution already changed the cursor'
            );
          }
          return;
        }
        // Google permanently rejecting the refresh token (revoked by the
        // user at their Google Account, or the app's access was removed)
        // manifests as invalid_grant / a 401. This connection can never
        // succeed again without the user reconnecting — mark it so the
        // webhook handler stops enqueueing sync jobs for it, rather than
        // retrying forever against a dead credential.
        const isPermanentAuthFailure =
          gmailError.code === 401 ||
          gmailError.response?.data?.error === 'invalid_grant' ||
          (gmailError.message && gmailError.message.includes('invalid_grant'));
        if (isPermanentAuthFailure) {
          logger.error({ integrationId }, 'Gmail credential permanently invalid (revoked?); marking connection ERROR');
          // Field-scoped compare-and-swap (Phase 10F): this execution read
          // status='ACTIVE' at job start (the early-return guard above
          // guarantees that), but the user may have disconnected the
          // integration (status -> 'DISCONNECTED', credentials cleared)
          // while this execution was still in flight. An unconditional write
          // here would overwrite that newer, deliberate, user-initiated
          // state with a stale ERROR classification from credentials that
          // are no longer even in use. Guarding on `status: 'ACTIVE'` means
          // this write only lands if nothing else has changed the status
          // since this execution observed it; only status is touched — never
          // accessToken, refreshToken, expiresAt, or historyId.
          const errorUpdateResult = await prisma.integration.updateMany({
            where: { id: integrationId, status: 'ACTIVE' },
            data: { status: 'ERROR' }
          });

          if (errorUpdateResult.count === 0) {
            // No token, header, or credential content is logged here — only
            // the integrationId, matching this file's existing convention.
            logger.info(
              { integrationId },
              'Gmail sync ERROR status not persisted: integration already changed state'
            );
          } else {
            // Only alert when this execution actually made the transition
            // (errorUpdateResult.count > 0) — never on a retry that finds
            // the connection already marked ERROR, which would spam a
            // duplicate "Integration failure" alert for the same outage.
            const alertTitle = 'Gmail integration failure';
            const createdAlert = await prisma.alert.create({
              data: {
                organizationId: integration.organizationId,
                title: alertTitle,
                message: `The Gmail connection for ${integration.emailAddress} has failed (credential invalid or revoked) and sync has stopped. Reconnect it under Integrations.`,
                severity: 'HIGH',
              },
            });
            await publishNotification(this.notificationRedis, {
              type: 'ALERT_CREATED',
              organizationId: integration.organizationId,
              alertId: createdAlert.id,
              severity: 'HIGH',
              title: alertTitle,
              timestamp: new Date().toISOString(),
            });
          }
          return;
        }
        // Any other page-level failure (including on page 2+) propagates:
        // messages already ingested from earlier pages in this call stay
        // ingested (sha256 dedup makes a retried page-1 refetch safe), but
        // the cursor is never advanced past history this sync never saw.
        throw error;
      }

      const history = historyResponse.data.history || [];
      latestHistoryId = historyResponse.data.historyId || latestHistoryId;

      for (const record of history) {
        if (record.messagesAdded) {
          for (const messageAdded of record.messagesAdded) {
            const messageId = messageAdded.message?.id;
            if (!messageId) continue;

            try {
              const msg = await gmail.users.messages.get({
                userId: 'me',
                id: messageId,
                format: 'raw'
              });

              if (!msg.data.raw) continue;

              const rawDecoded = Buffer.from(msg.data.raw, 'base64url');
              const sha256 = crypto.createHash('sha256').update(rawDecoded).digest('hex');

              const existing = await prisma.email.findFirst({
                where: { sha256, organizationId: integration.organizationId }
              });
              const priority = 3;

              if (existing) {
                if (existing.analysisStatus !== 'COMPLETED' && existing.rawStorageKey) {
                  await prisma.$transaction((tx) => ensureEmailOutboxEvent(tx, {
                    organizationId: integration.organizationId,
                    emailId: existing.id,
                    stage: EmailProcessingStage.PROCESSING,
                    queueName: 'email-processing',
                    jobName: 'process-email',
                    priority,
                    payload: {
                      organizationId: integration.organizationId,
                      resourceId: existing.id,
                      jobId: `ingest-${existing.id}`,
                      emailId: existing.id,
                      operation: 'ingest',
                      requestId: generateRequestId(),
                      storageReference: existing.rawStorageKey,
                      rawSha256: existing.sha256,
                      source: existing.ingestionSrc,
                    },
                  }));
                }
                continue;
              }

              const storageKey = `emails/${integration.organizationId}/${sha256}.eml`;
              await this.rawEmailStore.put(storageKey, Readable.from(rawDecoded));

              const requestId = generateRequestId();
              await prisma.$transaction(async (tx) => {
                const emailRecord = await tx.email.create({
                  data: {
                    organizationId: integration.organizationId,
                    rawStorageKey: storageKey,
                    sha256,
                    analysisStatus: 'PENDING',
                    ingestionSrc: 'GMAIL',
                  }
                });
                await ensureEmailOutboxEvent(tx, {
                  organizationId: integration.organizationId,
                  emailId: emailRecord.id,
                  stage: EmailProcessingStage.PROCESSING,
                  queueName: 'email-processing',
                  jobName: 'process-email',
                  priority,
                  payload: {
                    organizationId: integration.organizationId,
                    resourceId: emailRecord.id,
                    jobId: `ingest-${emailRecord.id}`,
                    emailId: emailRecord.id,
                    operation: 'ingest',
                    requestId,
                    storageReference: storageKey,
                    rawSha256: sha256,
                    source: 'GMAIL',
                  },
                });
              });

              logger.info({ organizationId: integration.organizationId, messageId }, 'Persisted Gmail message and processing intent');

            } catch (err) {
              logger.error({ err, messageId }, 'Failed to process message from history');
            }
          }
        }
      }

      pageToken = historyResponse.data.nextPageToken || undefined;
    } while (pageToken);

    // Persist Gmail's own authoritative historyId from the LAST page's
    // response, not the caller-supplied newHistoryId: the webhook payload is
    // an external, unauthenticated-at-this-layer hint, and even a fully
    // trustworthy caller can race with a concurrent notification. Trusting
    // it directly as the next sync's cursor risks silently skipping
    // unprocessed messages. This line is only reached once the pagination
    // loop above has exhausted every page (no nextPageToken remains) — if
    // any page's fetch failed, we already returned/threw above without
    // reaching here, so the cursor can never advance past history this sync
    // never actually saw. newHistoryId is only a fallback for the
    // never-expected case where Gmail's response omits its own historyId.
    //
    // Written as a compare-and-swap, not an unconditional update: two
    // concurrent executions for the same Integration (Phase 10D proved this
    // is a real, reachable interleaving, not merely theoretical) can each
    // independently reach this line with a different final historyId. An
    // unconditional write lets whichever execution's write lands LAST win,
    // regardless of which one's value is actually newer — this can regress
    // the cursor backward. Guarding the write with `historyId:
    // originalHistoryId` (the value this execution itself read at the top of
    // process()) means the write only succeeds if nothing else has changed
    // the cursor in between; if another execution already advanced it, this
    // one's update affects zero rows and is treated as an expected
    // concurrency outcome, not an error — whatever the other execution
    // already committed is left in place rather than being overwritten by
    // this potentially-stale value.
    const candidateHistoryId = latestHistoryId || newHistoryId;
    const cursorUpdateResult = await prisma.integration.updateMany({
      where: { id: integrationId, historyId: originalHistoryId },
      data: { historyId: candidateHistoryId }
    });

    if (cursorUpdateResult.count === 0) {
      // No token, header, or MIME content is logged here — only the
      // integrationId and a generic description of the race, matching this
      // file's existing logging convention.
      logger.info(
        { integrationId },
        'Gmail sync cursor not persisted: another concurrent execution already advanced it'
      );
    }
  }
}
