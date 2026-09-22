import { FastifyInstance } from 'fastify';
import crypto from 'crypto';
import { prisma } from '@ciperscope/database';
import { env, encryptToken, requireGmailTokenEncryptionKey } from '@ciperscope/config';
import { QueueManager } from '@ciperscope/queue';
import {
  fastifyCreateWebhookBodySchema,
  fastifyUpdateWebhookBodySchema,
  fastifyWebhookParamsSchema,
} from '../../utils/validation';
import { logAuditEvent } from '../../utils/audit';

const queueManager = new QueueManager(env.REDIS_URL || 'redis://127.0.0.1:6379');

/** Never include secretEncrypted in any API response — this is the one
 *  place a Webhook row is shaped for output, so every route reuses it. */
function toPublicWebhook(webhook: {
  id: string;
  organizationId: string;
  url: string;
  events: unknown;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: webhook.id,
    organizationId: webhook.organizationId,
    url: webhook.url,
    events: webhook.events,
    enabled: webhook.enabled,
    createdAt: webhook.createdAt,
    updatedAt: webhook.updatedAt,
  };
}

export default async function webhookRoutes(server: FastifyInstance) {
  server.post('/', {
    schema: { body: fastifyCreateWebhookBodySchema },
    preValidation: [server.authenticate, server.requirePermission('INTEGRATION_MANAGE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const { url, events, enabled } = request.body as { url: string; events: string[]; enabled: boolean };

    if (env.NODE_ENV === 'production' && !url.startsWith('https://')) {
      return reply.status(400).send({ error: 'Bad Request', message: 'Webhook URL must use HTTPS in production' });
    }

    // Generated here, shown to the caller exactly once, never persisted or
    // logged in plaintext again.
    const plaintextSecret = crypto.randomBytes(32).toString('hex');
    const secretEncrypted = encryptToken(plaintextSecret, requireGmailTokenEncryptionKey());

    const webhook = await prisma.webhook.create({
      data: {
        organizationId,
        url,
        secretEncrypted,
        events,
        enabled,
      },
    });

    await logAuditEvent({
      action: 'WEBHOOK_CREATED',
      resource: 'Webhook',
      resourceId: webhook.id,
      actorId: request.user?.sub,
      organizationId,
      status: 'SUCCESS',
      req: request,
    });

    return reply.status(201).send({ ...toPublicWebhook(webhook), secret: plaintextSecret });
  });

  server.get('/', {
    preValidation: [server.authenticate, server.requirePermission('INTEGRATION_MANAGE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const webhooks = await prisma.webhook.findMany({ where: { organizationId }, orderBy: { createdAt: 'desc' } });
    return reply.status(200).send({ webhooks: webhooks.map(toPublicWebhook) });
  });

  server.patch('/:webhookId', {
    schema: { params: fastifyWebhookParamsSchema, body: fastifyUpdateWebhookBodySchema },
    preValidation: [server.authenticate, server.requirePermission('INTEGRATION_MANAGE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { webhookId } = request.params as { webhookId: string };
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const { url, events, enabled } = request.body as { url?: string; events?: string[]; enabled?: boolean };

    if (url && env.NODE_ENV === 'production' && !url.startsWith('https://')) {
      return reply.status(400).send({ error: 'Bad Request', message: 'Webhook URL must use HTTPS in production' });
    }

    try {
      const webhook = await prisma.webhook.update({
        where: { id_organizationId: { id: webhookId, organizationId } },
        data: {
          ...(url !== undefined && { url }),
          ...(events !== undefined && { events }),
          ...(enabled !== undefined && { enabled }),
        },
      });

      await logAuditEvent({
        action: 'WEBHOOK_UPDATED',
        resource: 'Webhook',
        resourceId: webhook.id,
        actorId: request.user?.sub,
        organizationId,
        status: 'SUCCESS',
        req: request,
      });

      return reply.status(200).send(toPublicWebhook(webhook));
    } catch (err: any) {
      if (err.code === 'P2025') {
        return reply.status(404).send({ error: 'Not Found', message: 'Webhook not found' });
      }
      throw err;
    }
  });

  server.delete('/:webhookId', {
    schema: { params: fastifyWebhookParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('INTEGRATION_MANAGE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { webhookId } = request.params as { webhookId: string };
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    try {
      await prisma.webhook.delete({ where: { id_organizationId: { id: webhookId, organizationId } } });

      await logAuditEvent({
        action: 'WEBHOOK_DELETED',
        resource: 'Webhook',
        resourceId: webhookId,
        actorId: request.user?.sub,
        organizationId,
        status: 'SUCCESS',
        req: request,
      });

      return reply.status(204).send();
    } catch (err: any) {
      if (err.code === 'P2025') {
        return reply.status(404).send({ error: 'Not Found', message: 'Webhook not found' });
      }
      throw err;
    }
  });

  server.post('/:webhookId/test', {
    schema: { params: fastifyWebhookParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('INTEGRATION_MANAGE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { webhookId } = request.params as { webhookId: string };
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const webhook = await prisma.webhook.findUnique({ where: { id_organizationId: { id: webhookId, organizationId } } });
    if (!webhook) {
      return reply.status(404).send({ error: 'Not Found', message: 'Webhook not found' });
    }

    const eventId = crypto.randomUUID();
    // BullMQ rejects ':' in custom job IDs (its own Redis-key delimiter).
    const jobId = `${eventId}_${webhook.id}`;
    const queue = queueManager.getQueue('webhook-delivery');
    await queue.add('deliver', {
      organizationId,
      resourceId: webhook.id,
      jobId,
      operation: 'webhook_delivery_test',
      webhookId: webhook.id,
      eventId,
      eventType: 'WEBHOOK_TEST',
      payload: {
        eventType: 'WEBHOOK_TEST',
        eventId,
        organizationId,
        message: 'This is a test delivery from CipherScope.',
        timestamp: new Date().toISOString(),
      },
    }, { jobId });

    await logAuditEvent({
      action: 'WEBHOOK_TEST_TRIGGERED',
      resource: 'Webhook',
      resourceId: webhook.id,
      actorId: request.user?.sub,
      organizationId,
      status: 'SUCCESS',
      req: request,
    });

    return reply.status(202).send({ message: 'Test delivery enqueued', eventId });
  });
}
