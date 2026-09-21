import { google } from 'googleapis';
import { prisma } from '@ciperscope/database';
import { env, decryptToken, encryptToken, requireGmailTokenEncryptionKey } from '@ciperscope/config';
import { logger, generateRequestId } from '@ciperscope/logger';
import { RawEmailStore } from '@ciperscope/storage';
import { QueueManager, EmailIngestionJobPayload } from '@ciperscope/queue';
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
  private queueManager: QueueManager;

  constructor(private rawEmailStore: RawEmailStore) {
    this.queueManager = new QueueManager(env.REDIS_URL);
  }

  async process(jobData: GmailSyncJobPayload) {
    const { integrationId, newHistoryId } = jobData;

    const integration = await prisma.integration.findUnique({
      where: { id: integrationId }
    });

    if (!integration) {
      throw new Error(`Integration ${integrationId} not found`);
    }

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

    oauth2Client.on('tokens', async (tokens) => {
      await prisma.integration.update({
        where: { id: integrationId },
        data: {
          accessToken: encryptToken(tokens.access_token!, encryptionKey),
          ...(tokens.refresh_token ? { refreshToken: encryptToken(tokens.refresh_token, encryptionKey) } : {}),
          ...(tokens.expiry_date ? { expiresAt: new Date(tokens.expiry_date) } : {})
        }
      });
    });

    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    const emailQueue = this.queueManager.getQueue('email-processing');

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
          await prisma.integration.update({
            where: { id: integrationId },
            data: { historyId: newHistoryId }
          });
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
          await prisma.integration.update({
            where: { id: integrationId },
            data: { status: 'ERROR' }
          });
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

              if (existing) continue;

              const storageKey = `emails/${integration.organizationId}/${sha256}.eml`;
              await this.rawEmailStore.put(storageKey, Readable.from(rawDecoded));

              const priority = 3;

              const emailRecord = await prisma.email.create({
                data: {
                  organizationId: integration.organizationId,
                  rawStorageKey: storageKey,
                  sha256,
                  analysisStatus: 'PENDING'
                }
              });

              const payload: EmailIngestionJobPayload = {
                organizationId: integration.organizationId,
                resourceId: emailRecord.id,
                jobId: `ingest-${emailRecord.id}`,
                operation: 'ingest',
                emailId: emailRecord.id,
                storageReference: storageKey,
                rawSha256: sha256,
                source: 'GMAIL',
                requestId: generateRequestId()
              };

              await emailQueue.add('ingest', payload, {
                priority,
                jobId: payload.jobId
              });

              logger.info({ emailId: emailRecord.id, messageId }, 'Enqueued Gmail message for processing');

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
    await prisma.integration.update({
      where: { id: integrationId },
      data: { historyId: latestHistoryId || newHistoryId }
    });
  }
}
