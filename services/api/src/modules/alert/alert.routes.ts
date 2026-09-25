import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { env } from '@ciperscope/config';
import {
  fastifyAlertListQuerySchema,
  fastifyGlobalAlertParamsSchema,
  fastifyUpdateAlertBodySchema,
  fastifyAlertUnreadCountQuerySchema,
  fastifyAlertStreamQuerySchema,
} from '../../utils/validation';
import { z } from 'zod';
import { logAuditEvent } from '../../utils/audit';
import { userHasPermissionInOrg } from '../../utils/permissionCheck';
import { isSessionValid } from '../../utils/sessionCheck';
import { notificationHub } from './notificationHub';

export default async function alertRoutes(server: FastifyInstance) {
  /**
   * Real-time push for the header notification bell (apps/web/src/
   * components/NotificationBell.tsx): Server-Sent Events, backed by the
   * same Alert model/table GET / and PATCH /:alertId already use — never a
   * second notification model. Worker publishes ALERT_CREATED over Redis
   * pub/sub (packages/queue/src/notificationChannel.ts) when it persists a
   * CRITICAL/HIGH Alert or a Gmail-integration-failure Alert; this API
   * process relays it to every connected browser for that organization.
   *
   * EventSource cannot send custom headers or a request body, so:
   *  - auth arrives via the httpOnly `accessToken` cookie (EventSource's
   *    `withCredentials: true`), verified manually below exactly like
   *    rbac.ts's `authenticate` hook does (same isSessionValid() check).
   *  - tenant context arrives as `?organizationId=` instead of the usual
   *    x-organization-id header, but is validated against the
   *    authenticated user's real memberships via the SAME
   *    userHasPermissionInOrg() check requirePermission() uses — never
   *    trusted on its own, and a user can never subscribe to an
   *    organization they don't belong to.
   */
  server.get('/stream', {
    schema: { querystring: fastifyAlertStreamQuerySchema },
  }, async (request, reply) => {
    try {
      await request.jwtVerify();
    } catch {
      return reply.status(401).send({ error: 'Unauthorized', message: 'Invalid or missing token' });
    }
    if (request.user.sid && !(await isSessionValid(request.user.sid))) {
      return reply.status(401).send({ error: 'Unauthorized', message: 'Session is invalid or revoked' });
    }

    const { organizationId } = request.query as { organizationId: string };
    if (!request.user.orgs.includes(organizationId)) {
      return reply.status(403).send({ error: 'Forbidden', message: 'Tenant isolation violation' });
    }
    const allowed = await userHasPermissionInOrg(request.user.sub, organizationId, 'ALERT_READ');
    if (!allowed) {
      await logAuditEvent({
        action: 'AUTHZ_DENIED', resource: 'ALERT_READ', status: 'DENIED',
        organizationId, actorId: request.user.sub, req: request,
      });
      return reply.status(403).send({ error: 'Forbidden', message: 'Missing required permission: ALERT_READ' });
    }

    // Hands the raw response over to us — Fastify's normal reply
    // lifecycle (serialization, onSend hooks) never runs, since this
    // response is a long-lived stream, not a single JSON payload. That
    // includes @fastify/cors's own onSend hook, which is where it adds
    // Access-Control-Allow-Origin/-Credentials — so this route must set
    // those two headers itself, using the exact same allowlist
    // (env.CORS_ORIGIN) and credentials:true policy configured for the
    // plugin in services/api/src/index.ts, or the browser silently blocks
    // the whole response as a CORS violation (it did during development:
    // the connection opened and streamed correctly at the TCP/HTTP level —
    // confirmed with curl — while every browser fetch/EventSource attempt
    // failed with a generic, header-free "Failed to fetch").
    const requestOrigin = request.headers.origin;
    const corsHeaders: Record<string, string> = {};
    const allowedOrigins = env.CORS_ORIGIN.split(',').map(o => o.trim());
    if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
      corsHeaders['Access-Control-Allow-Origin'] = requestOrigin;
      corsHeaders['Access-Control-Allow-Credentials'] = 'true';
      corsHeaders['Vary'] = 'Origin';
    }

    reply.hijack();
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      // Disables response buffering on nginx-style reverse proxies, which
      // would otherwise hold every event until the buffer fills —
      // defeating the entire point of a push channel. A harmless no-op
      // when there's no such proxy in front of this API.
      'X-Accel-Buffering': 'no',
      ...corsHeaders,
    });
    // Tells a reconnecting EventSource how long to wait before retrying,
    // and flushes the headers immediately so the browser's connection
    // opens right away rather than waiting for the first real event.
    reply.raw.write('retry: 5000\n\n');

    const unsubscribe = await notificationHub.subscribeOrg(organizationId, (event) => {
      reply.raw.write(`event: notification\ndata: ${JSON.stringify(event)}\n\n`);
    });

    // Keeps intermediary proxies/load balancers from silently closing an
    // otherwise-idle-looking long-lived connection, and lets the browser
    // detect a dead connection faster than its own TCP timeout would.
    const heartbeat = setInterval(() => {
      reply.raw.write(': heartbeat\n\n');
    }, 25000);

    const cleanup = () => {
      clearInterval(heartbeat);
      void unsubscribe();
    };
    request.raw.on('close', cleanup);
    request.raw.on('error', cleanup);
    reply.raw.on('close', cleanup);
    reply.raw.on('error', cleanup);
  });
  server.get('/unread-count', {
    schema: { querystring: fastifyAlertUnreadCountQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('ALERT_READ')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }
    const { severity } = request.query as { severity?: string };
    const count = await prisma.alert.count({
      where: { organizationId, isRead: false, ...(severity ? { severity: severity as any } : {}) },
    });
    return reply.status(200).send({ count });
  });

  server.post('/mark-all-read', {
    preValidation: [server.authenticate, server.requirePermission('ALERT_UPDATE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }
    const result = await prisma.alert.updateMany({
      where: { organizationId, isRead: false },
      data: { isRead: true },
    });

    await logAuditEvent({
      action: 'ALERTS_MARKED_ALL_READ', resource: 'Alert', resourceId: organizationId,
      organizationId, actorId: request.user?.sub, status: 'SUCCESS', req: request,
      metadata: { count: result.count },
    });

    return reply.status(200).send({ count: result.count });
  });

  server.get('/', {
    schema: { querystring: fastifyAlertListQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('ALERT_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const query = request.query as any;
    const limit = query.limit;

    let cursorOpt: any = undefined;
    if (query.cursor) {
      try {
        const decodedString = Buffer.from(query.cursor, 'base64').toString('utf-8');
        const decoded = JSON.parse(decodedString);
        cursorOpt = { id: decoded[1] };
      } catch (err) {
        return reply.status(400).send({ error: 'Bad Request', message: 'Malformed cursor' });
      }
    }

    const where: any = { organizationId };
    if (query.severity) where.severity = query.severity;
    if (query.isRead !== undefined) where.isRead = query.isRead;

    try {
      const items = await prisma.alert.findMany({
        where,
        take: limit + 1,
        skip: cursorOpt ? 1 : 0,
        cursor: cursorOpt,
        orderBy: [
          { createdAt: query.direction || 'desc' },
          { id: query.direction || 'desc' }
        ],
      });

      let nextCursor: string | null = null;
      if (items.length > limit) {
        items.pop();
        const lastItem = items[items.length - 1];
        if (lastItem) {
          nextCursor = Buffer.from(JSON.stringify([lastItem.createdAt.toISOString(), lastItem.id])).toString('base64');
        }
      }

      return reply.status(200).send({ items, nextCursor });
    } catch (err: any) {
      if (err.code === 'P2025') {
        return reply.status(400).send({ error: 'Bad Request', message: 'Invalid cursor: record not found or inaccessible' });
      }
      throw err;
    }
  });

  server.patch('/:alertId', {
    schema: {
      params: fastifyGlobalAlertParamsSchema,
      body: fastifyUpdateAlertBodySchema
    },
    preValidation: [server.authenticate, server.requirePermission('ALERT_UPDATE')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { alertId } = request.params as { alertId: string };
    const { isRead } = request.body as { isRead: boolean };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    try {
      const alert = await prisma.alert.update({
        where: { id: alertId, organizationId },
        data: { isRead }
      });

      await logAuditEvent({
        action: 'CASE_ALERT_UPDATED',
        resource: 'Alert',
        resourceId: alert.id,
        actorId: request.user?.sub,
        status: 'SUCCESS',
        metadata: { isRead },
        req: request
      });

      return reply.status(200).send(alert);
    } catch (err: any) {
      if (err.code === 'P2025') {
        return reply.status(404).send({ error: 'Not Found', message: 'Alert not found' });
      }
      throw err;
    }
  });
}
