import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '@ciperscope/database';
import { env, encryptToken, decryptToken, requireGmailTokenEncryptionKey } from '@ciperscope/config';
import { google } from 'googleapis';
import { QueueManager } from '@ciperscope/queue';
import { logAuditEvent } from '../../utils/audit';
import { issueGmailOAuthState, verifyAndConsumeGmailOAuthState, OAuthStateError } from './oauthState';

const CallbackQuerySchema = z.object({
  code: z.string(),
  state: z.string()
});

const WebhookBodySchema = z.object({
  message: z.object({
    data: z.string(),
    messageId: z.string(),
    publishTime: z.string()
  }),
  subscription: z.string()
});

export default async function integrationRoutes(server: FastifyInstance) {
  const getOauth2Client = () => {
    return new google.auth.OAuth2(
      env.GOOGLE_CLIENT_ID,
      env.GOOGLE_CLIENT_SECRET,
      env.GOOGLE_OAUTH_REDIRECT_URI
    );
  };

  server.get('/gmail/auth', {
    preValidation: [server.authenticate],
    schema: {
      tags: ['Integrations'],
      summary: 'Start Gmail OAuth Flow'
    }
  }, async (request, reply) => {
    const organizationId = (request.query as any).organizationId || request.user.orgs?.[0];
    if (!organizationId) {
      return reply.code(400).send({ error: 'Missing organizationId' });
    }
    // Tenant safety: never let the caller bind the OAuth flow to an
    // organization they don't actually belong to, regardless of what the
    // ?organizationId query param says.
    if (!request.user.orgs?.includes(organizationId)) {
      return reply.code(403).send({ error: 'Forbidden', message: 'Tenant isolation violation' });
    }

    requireGmailTokenEncryptionKey(); // fail fast, before starting a flow we couldn't complete

    const oauth2Client = getOauth2Client();
    const stateToken = issueGmailOAuthState(server, request.user.sub, organizationId);

    const url = oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: ['https://www.googleapis.com/auth/gmail.readonly'],
      state: stateToken,
      prompt: 'consent'
    });

    return reply.redirect(url, 302);
  });

  server.get('/gmail/callback', {
    schema: {
      tags: ['Integrations'],
      summary: 'Gmail OAuth Callback'
    }
  }, async (request, reply) => {
    const frontendUrl = (status: 'success' | 'error') => {
      const baseOrigin = Array.isArray(env.CORS_ORIGIN) ? env.CORS_ORIGIN[0] : (env.CORS_ORIGIN || 'http://localhost:5173');
      const url = new URL('/settings/integrations', baseOrigin);
      url.searchParams.set('integration', status);
      return url.toString();
    };

    const query = CallbackQuerySchema.safeParse(request.query);
    if (!query.success) {
      server.log.error({ err: query.error }, 'Invalid callback query parameters');
      return reply.redirect(frontendUrl('error'), 302);
    }

    let organizationId: string;
    let initiatingUserId: string;
    try {
      const verified = await verifyAndConsumeGmailOAuthState(server, query.data.state);
      organizationId = verified.organizationId;
      initiatingUserId = verified.userId;
    } catch (err) {
      const message = err instanceof OAuthStateError ? err.message : 'OAuth state verification failed';
      server.log.warn({ err: message }, 'Rejected Gmail OAuth callback: invalid state');
      await logAuditEvent({
        action: 'INTEGRATION_GMAIL_OAUTH_REJECTED',
        resource: 'Integration',
        status: 'DENIED',
        metadata: { reason: message },
        req: request
      });
      return reply.redirect(frontendUrl('error'), 302);
    }

    try {
      const encryptionKey = requireGmailTokenEncryptionKey();
      const oauth2Client = getOauth2Client();
      const { tokens } = await oauth2Client.getToken(query.data.code);
      oauth2Client.setCredentials(tokens);

      const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
      const profile = await gmail.users.getProfile({ userId: 'me' });
      const emailAddress = profile.data.emailAddress;

      if (!emailAddress) {
        throw new Error('Failed to get email address from Gmail profile');
      }
      if (!tokens.access_token) {
        throw new Error('Google did not return an access token');
      }

      // A mailbox can only ever be connected to ONE organization at a time
      // (enforced by the Integration.provider_emailAddress unique index —
      // see packages/database/prisma/schema.prisma). Reject rather than
      // silently reassigning ownership if another org already owns it.
      const existingElsewhere = await prisma.integration.findUnique({
        where: { provider_emailAddress: { provider: 'GMAIL', emailAddress } }
      });
      if (existingElsewhere && existingElsewhere.organizationId !== organizationId) {
        server.log.warn({ emailAddress }, 'Rejected Gmail connect: mailbox already connected to a different organization');
        await logAuditEvent({
          action: 'INTEGRATION_GMAIL_OAUTH_REJECTED',
          resource: 'Integration',
          actorId: initiatingUserId,
          organizationId,
          status: 'DENIED',
          metadata: { reason: 'mailbox_already_connected_to_another_org' },
          req: request
        });
        return reply.redirect(frontendUrl('error'), 302);
      }

      await prisma.integration.upsert({
        where: {
          organizationId_provider_emailAddress: {
            organizationId,
            provider: 'GMAIL',
            emailAddress
          }
        },
        create: {
          organizationId,
          provider: 'GMAIL',
          emailAddress,
          accessToken: encryptToken(tokens.access_token, encryptionKey),
          refreshToken: encryptToken(tokens.refresh_token ?? '', encryptionKey),
          expiresAt: new Date(tokens.expiry_date!),
          historyId: profile.data.historyId?.toString(),
          status: 'ACTIVE'
        },
        update: {
          accessToken: encryptToken(tokens.access_token, encryptionKey),
          ...(tokens.refresh_token ? { refreshToken: encryptToken(tokens.refresh_token, encryptionKey) } : {}),
          expiresAt: new Date(tokens.expiry_date!),
          status: 'ACTIVE'
        }
      });

      if (env.GOOGLE_PUBSUB_TOPIC) {
        await gmail.users.watch({
          userId: 'me',
          requestBody: {
            topicName: env.GOOGLE_PUBSUB_TOPIC,
            labelIds: ['INBOX']
          }
        });
        server.log.info({ organizationId, emailAddress }, 'Successfully subscribed to Gmail push notifications');
      }

      await logAuditEvent({
        action: 'INTEGRATION_GMAIL_CONNECTED',
        resource: 'Integration',
        actorId: initiatingUserId,
        organizationId,
        status: 'SUCCESS',
        metadata: { emailAddress },
        req: request
      });

      return reply.redirect(frontendUrl('success'), 302);

    } catch (error) {
      server.log.error({ err: error }, 'Failed to process Gmail callback');
      return reply.redirect(frontendUrl('error'), 302);
    }
  });

  server.post('/gmail/webhook', {
    schema: {
      tags: ['Integrations'],
      summary: 'Gmail Push Notification Webhook'
    }
  }, async (request, reply) => {
    reply.code(200).send();

    try {
      const body = WebhookBodySchema.parse(request.body);
      const dataStr = Buffer.from(body.message.data, 'base64').toString('utf-8');
      const data = JSON.parse(dataStr);

      const emailAddress = data.emailAddress;
      const newHistoryId = data.historyId;

      if (!emailAddress) {
        server.log.warn('Webhook received without email address');
        return;
      }

      // Google's Gmail push-notification payload identifies the mailbox
      // only by emailAddress — it never carries our organizationId (a real
      // external protocol constraint). This lookup is safe from
      // cross-tenant ambiguity because Integration.(provider, emailAddress)
      // is a database-enforced unique key: a given mailbox can only ever
      // belong to one organization's connection record at a time.
      const integration = await prisma.integration.findUnique({
        where: { provider_emailAddress: { provider: 'GMAIL', emailAddress } }
      });

      if (!integration) {
        server.log.warn({ emailAddress }, 'Received webhook for unknown integration');
        return;
      }

      if (integration.status !== 'ACTIVE') {
        server.log.warn({ emailAddress, status: integration.status }, 'Ignoring webhook for inactive/disconnected integration');
        return;
      }

      const queueManager = new QueueManager(env.REDIS_URL);
      const syncQueue = queueManager.getQueue('gmail-sync');

      await syncQueue.add(
        'sync-history',
        {
          integrationId: integration.id,
          organizationId: integration.organizationId,
          emailAddress,
          newHistoryId
        },
        {
          priority: 3,
          jobId: `sync-${integration.id}-${newHistoryId}`
        }
      );

      server.log.info({ emailAddress, newHistoryId }, 'Enqueued gmail-sync job');

    } catch (error) {
      server.log.error({ err: error }, 'Failed to process Gmail webhook');
    }
  });

  // The frontend previously had no way to know whether Gmail was actually
  // connected except by reading a one-time `?integration=success` query
  // param right after the OAuth callback redirect — a page refresh lost
  // that state entirely, showing "not connected" even for a genuinely
  // active integration. This is the real status source it was missing.
  // Never returns accessToken/refreshToken — only the fields needed to
  // render connection state in the UI.
  server.get('/gmail/connection', {
    preValidation: [server.authenticate, server.requirePermission('INTEGRATION_MANAGE')],
    schema: {
      tags: ['Integrations'],
      summary: 'Get current Gmail connection status for this organization'
    }
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;

    const integration = await prisma.integration.findFirst({
      where: { organizationId, provider: 'GMAIL', status: 'ACTIVE' },
      select: { emailAddress: true, status: true, createdAt: true, updatedAt: true },
      orderBy: { updatedAt: 'desc' }
    });

    if (!integration) {
      return reply.code(200).send({ status: 'not_connected' });
    }

    return reply.code(200).send({
      status: 'connected',
      emailAddress: integration.emailAddress,
      connectedAt: integration.createdAt,
      lastUpdatedAt: integration.updatedAt
    });
  });

  server.delete('/gmail/connection', {
    preValidation: [server.authenticate, server.requirePermission('INTEGRATION_MANAGE')],
    schema: {
      tags: ['Integrations'],
      summary: 'Disconnect Gmail integration'
    }
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const userId = request.user?.sub;

    const activeConnections = await prisma.integration.findMany({
      where: { organizationId, provider: 'GMAIL', status: 'ACTIVE' }
    });

    if (activeConnections.length === 0) {
      // Idempotent: calling disconnect when nothing is connected is a
      // no-op success, not an error.
      return reply.code(200).send({ status: 'not_connected' });
    }

    const encryptionKey = requireGmailTokenEncryptionKey();

    for (const integration of activeConnections) {
      let refreshToken: string | null = null;
      let accessToken: string | null = null;
      try {
        refreshToken = decryptToken(integration.refreshToken, encryptionKey) || null;
        accessToken = decryptToken(integration.accessToken, encryptionKey) || null;
      } catch (err) {
        server.log.warn({ err, integrationId: integration.id }, 'Could not decrypt stored Gmail tokens during disconnect; proceeding with local cleanup only');
      }

      const oauth2Client = getOauth2Client();

      // Best-effort revocation at Google. A failure here (e.g. already
      // revoked by the user from their Google Account settings) must never
      // block local cleanup.
      if (refreshToken) {
        try {
          await oauth2Client.revokeToken(refreshToken);
        } catch (err) {
          server.log.warn({ err, integrationId: integration.id }, 'Gmail token revocation at Google failed (continuing with local disconnect)');
        }
      }

      // Best-effort stop of push notifications.
      if (accessToken) {
        try {
          oauth2Client.setCredentials({ access_token: accessToken });
          const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
          await gmail.users.stop({ userId: 'me' });
        } catch (err) {
          server.log.warn({ err, integrationId: integration.id }, 'Gmail watch-stop failed (continuing with local disconnect)');
        }
      }

      // Local invalidation: clear the stored credentials (never leave a
      // usable token at rest) and mark the connection DISCONNECTED so the
      // webhook handler and sync worker will never act on it again, while
      // preserving the row itself as a forensic record that this mailbox
      // was once connected.
      await prisma.integration.update({
        where: { id: integration.id },
        data: {
          status: 'DISCONNECTED',
          accessToken: encryptToken('', encryptionKey),
          refreshToken: encryptToken('', encryptionKey)
        }
      });

      await logAuditEvent({
        action: 'INTEGRATION_GMAIL_DISCONNECTED',
        resource: 'Integration',
        resourceId: integration.id,
        actorId: userId,
        organizationId,
        status: 'SUCCESS',
        metadata: { emailAddress: integration.emailAddress },
        req: request
      });
    }

    return reply.code(200).send({ status: 'disconnected', count: activeConnections.length });
  });
}
