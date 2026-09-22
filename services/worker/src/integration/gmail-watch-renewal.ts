import { google } from 'googleapis';
import { prisma } from '@ciperscope/database';
import { env, decryptToken, requireGmailTokenEncryptionKey } from '@ciperscope/config';
import { logger } from '@ciperscope/logger';

export interface GmailWatchRenewalResult {
  renewed: number;
  failed: number;
  skipped: number;
}

/**
 * Re-registers the Gmail push-notification watch for every ACTIVE Gmail
 * Integration. Google's watch subscriptions expire after a maximum of 7
 * days (https://developers.google.com/gmail/api/guides/push) and, before
 * this file existed, were never renewed anywhere in this codebase — the
 * one call site (services/api/src/modules/integration/integration.routes.ts)
 * only registers a watch once, at initial OAuth connection. Without
 * periodic renewal, automatic email detection silently stops after at
 * most 7 days, with no error surfaced anywhere (Phase 10G).
 *
 * Deliberately does NOT persist anything to Integration on success: the
 * Integration schema has no field for watch/channel/expiration state, and
 * adding one would be a schema change this phase explicitly avoids (a
 * fixed renewal period safely under Google's 7-day maximum makes tracking
 * the exact expiration unnecessary). Deliberately does NOT modify
 * Integration.status or any credential field on a per-integration
 * failure: an invalid/expired credential is already correctly detected,
 * classified, and CAS-protected by GmailSyncWorker's own 401/invalid_grant
 * handler (services/worker/src/integration/gmail-sync.ts) the next time a
 * real sync runs for that integration — duplicating that state transition
 * here would create a second, divergent path to the same outcome. A
 * renewal failure is therefore treated as transient and simply retried on
 * the next scheduled run.
 */
export class GmailWatchRenewalWorker {
  async renewAll(): Promise<GmailWatchRenewalResult> {
    if (!env.GOOGLE_PUBSUB_TOPIC) {
      logger.warn('Gmail watch renewal skipped: GOOGLE_PUBSUB_TOPIC is not configured');
      return { renewed: 0, failed: 0, skipped: 0 };
    }

    const encryptionKey = requireGmailTokenEncryptionKey();

    // Only ACTIVE integrations are eligible. DISCONNECTED and ERROR
    // integrations are excluded by this query itself, not by a
    // post-fetch filter — there is no path in this file that can ever
    // act on a non-ACTIVE integration.
    const integrations = await prisma.integration.findMany({
      where: { provider: 'GMAIL', status: 'ACTIVE' }
    });

    let renewed = 0;
    let failed = 0;

    for (const integration of integrations) {
      try {
        const oauth2Client = new google.auth.OAuth2(
          env.GOOGLE_CLIENT_ID,
          env.GOOGLE_CLIENT_SECRET,
          env.GOOGLE_OAUTH_REDIRECT_URI
        );
        oauth2Client.setCredentials({
          access_token: decryptToken(integration.accessToken, encryptionKey),
          refresh_token: decryptToken(integration.refreshToken, encryptionKey)
        });

        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        // Re-registering an existing watch is safe and idempotent per
        // Google's own documented behavior — it simply resets the
        // subscription's expiration. No response field is read or
        // persisted here (see class doc comment above).
        await gmail.users.watch({
          userId: 'me',
          requestBody: {
            topicName: env.GOOGLE_PUBSUB_TOPIC,
            labelIds: ['INBOX']
          }
        });

        renewed++;
      } catch (err) {
        failed++;
        // No token, Authorization header, or credential content is logged
        // here — only the integrationId, matching this codebase's
        // established Gmail-integration logging convention.
        logger.warn(
          { integrationId: integration.id },
          'Gmail watch renewal failed for this integration; will retry on the next scheduled run'
        );
        void err; // error content intentionally not logged (may embed request context)
      }
    }

    logger.info({ renewed, failed, total: integrations.length }, 'Gmail watch renewal cycle complete');
    return { renewed, failed, skipped: 0 };
  }
}
