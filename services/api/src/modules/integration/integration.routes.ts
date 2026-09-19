import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { prisma } from '@ciperscope/database';
import { env } from '@ciperscope/config';
import { google } from 'googleapis';
import { QueueManager } from '@ciperscope/queue';

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
    const oauth2Client = getOauth2Client();
    const organizationId = (request.query as any).organizationId || request.user.orgs?.[0];
    if (!organizationId) {
      return reply.code(400).send({ error: 'Missing organizationId' });
    }
    const stateObj = { organizationId };
    const stateToken = Buffer.from(JSON.stringify(stateObj)).toString('base64');

    const url = oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: ['https://www.googleapis.com/auth/gmail.readonly'],
      state: stateToken,
      prompt: 'consent'
    });

    return reply.redirect(302, url);
  });

  server.get('/gmail/callback', {
    schema: {
      tags: ['Integrations'],
      summary: 'Gmail OAuth Callback'
    }
  }, async (request, reply) => {
    const query = CallbackQuerySchema.safeParse(request.query);
    if (!query.success) {
      server.log.error({ err: query.error }, 'Invalid callback query parameters');
      return reply.code(400).send({ error: 'Invalid parameters' });
    }

    try {
      const stateStr = Buffer.from(query.data.state, 'base64').toString('utf-8');
      const stateObj = JSON.parse(stateStr);
      const organizationId = stateObj.organizationId;

      if (!organizationId) {
        throw new Error('Missing organizationId in state');
      }

      const oauth2Client = getOauth2Client();
      const { tokens } = await oauth2Client.getToken(query.data.code);
      oauth2Client.setCredentials(tokens);

      const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
      const profile = await gmail.users.getProfile({ userId: 'me' });
      const emailAddress = profile.data.emailAddress;

      if (!emailAddress) {
        throw new Error('Failed to get email address from Gmail profile');
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
          accessToken: tokens.access_token!,
          refreshToken: tokens.refresh_token!,
          expiresAt: new Date(tokens.expiry_date!),
          historyId: profile.data.historyId?.toString()
        },
        update: {
          accessToken: tokens.access_token!,
          ...(tokens.refresh_token ? { refreshToken: tokens.refresh_token } : {}),
          expiresAt: new Date(tokens.expiry_date!)
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

      const frontendUrl = new URL('/settings/integrations', env.CORS_ORIGIN || 'http://localhost:5173');
      frontendUrl.searchParams.set('integration', 'success');
      return reply.redirect(302, frontendUrl.toString());

    } catch (error) {
      server.log.error({ err: error }, 'Failed to process Gmail callback');
      const frontendUrl = new URL('/settings/integrations', env.CORS_ORIGIN || 'http://localhost:5173');
      frontendUrl.searchParams.set('integration', 'error');
      return reply.redirect(302, frontendUrl.toString());
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

      const integration = await prisma.integration.findFirst({
        where: {
          provider: 'GMAIL',
          emailAddress
        }
      });

      if (!integration) {
        server.log.warn({ emailAddress }, 'Received webhook for unknown integration');
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
}
