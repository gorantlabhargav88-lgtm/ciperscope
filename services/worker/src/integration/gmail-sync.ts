import { google } from 'googleapis';
import { prisma } from '@ciperscope/database';
import { env } from '@ciperscope/config';
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

    const oauth2Client = new google.auth.OAuth2(
      env.GOOGLE_CLIENT_ID,
      env.GOOGLE_CLIENT_SECRET,
      env.GOOGLE_OAUTH_REDIRECT_URI
    );

    oauth2Client.setCredentials({
      access_token: integration.accessToken,
      refresh_token: integration.refreshToken
    });

    oauth2Client.on('tokens', async (tokens) => {
      await prisma.integration.update({
        where: { id: integrationId },
        data: {
          accessToken: tokens.access_token!,
          ...(tokens.refresh_token ? { refreshToken: tokens.refresh_token } : {}),
          ...(tokens.expiry_date ? { expiresAt: new Date(tokens.expiry_date) } : {})
        }
      });
    });

    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    let historyResponse;
    try {
      historyResponse = await gmail.users.history.list({
        userId: 'me',
        startHistoryId: integration.historyId || undefined,
        historyTypes: ['messageAdded']
      });
    } catch (error: any) {
      if (error.code === 404 || error.message.includes('HistoryId is invalid')) {
        logger.warn({ integrationId }, 'History ID expired or invalid, performing full sync (not fully implemented) - updating to new historyId');
        await prisma.integration.update({
          where: { id: integrationId },
          data: { historyId: newHistoryId }
        });
        return;
      }
      throw error;
    }

    const history = historyResponse.data.history || [];
    const emailQueue = this.queueManager.getQueue('email-processing');

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

    await prisma.integration.update({
      where: { id: integrationId },
      data: { historyId: newHistoryId }
    });
  }
}
