import Fastify, { FastifyInstance, FastifyError } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import fastifyCookie from '@fastify/cookie';
import fastifyCors from '@fastify/cors';
import fastifyHelmet from '@fastify/helmet';
import fastifyRateLimit from '@fastify/rate-limit';
import { prisma } from '@ciperscope/database';
import authRoutes from './modules/auth/auth.routes';
import rbacPlugin from './plugins/rbac';
import tolerantJsonBodyParser from './plugins/tolerantJsonBodyParser';
import emailRoutes from './modules/email/email.routes';
import caseRoutes from './modules/case/case.routes';
import dashboardRoutes from './modules/dashboard/dashboard.routes';
import alertRoutes from './modules/alert/alert.routes';
import investigationRoutes from './modules/investigation/investigation.routes';
import evidenceRoutes from './modules/evidence/evidence.routes';
import integrationRoutes from './modules/integration/integration.routes';
import webhookRoutes from './modules/webhook/webhook.routes';
import reportRoutes from './modules/report/report.routes';
import intelligenceRoutes from './modules/intelligence/intelligence.routes';
import analyticsRoutes from './modules/analytics/analytics.routes';
import auditRoutes from './modules/audit/audit.routes';
import membersRoutes from './modules/members/members.routes';
import settingsRoutes from './modules/settings/settings.routes';
import invitationRoutes from './modules/invitation/invitation.routes';
import fastifyMultipart from '@fastify/multipart';
import { createRedisConnection } from '@ciperscope/queue';

import { logger, loggerOptions, generateRequestId, runWithContext } from '@ciperscope/logger';
import { env } from '@ciperscope/config';

const server: FastifyInstance = Fastify({
  logger: loggerOptions,
  genReqId: () => generateRequestId(),
  // Prevent X-Forwarded-For spoofing by only trusting explicitly configured proxies
  trustProxy: env.TRUST_PROXY ? env.TRUST_PROXY.split(',') : false,
  ajv: {
    customOptions: {
      removeAdditional: false,
    },
  },
});

server.register(tolerantJsonBodyParser);

// Setup Request Context
server.addHook('onRequest', (request, reply, done) => {
  runWithContext(
    {
      requestId: request.id as string,
      userId: (request.user as { id?: string } | undefined)?.id, // If JWT populates request.user
    },
    () => done()
  );
});

// Centralized Error Handler
// Fastify v5's setErrorHandler infers `error` as `unknown` unless the
// FastifyError generic/annotation is supplied explicitly (v4 defaulted
// this to FastifyError) — a type-only change, not a runtime behavior
// change; error.validation is still populated identically at runtime.
server.setErrorHandler((error: FastifyError, request, reply) => {
  logger.error({ err: error }, 'Unhandled error occurred');
  
  if (error.validation) {
    return reply.status(400).send({
      error: 'Bad Request',
      message: 'Validation failed',
      details: error.validation,
    });
  }

  reply.status(500).send({
    error: 'Internal Server Error',
    message: 'An unexpected error occurred',
  });
});

import fastifyMetrics from 'fastify-metrics';

// Register Core Security Plugins
server.register(fastifyHelmet);
server.register(fastifyCors, {
  origin: env.CORS_ORIGIN,
  credentials: true,
  // @fastify/cors 9→11 (this session's Fastify 5 migration) silently
  // changed its default `methods` from allowing everything to
  // 'GET,HEAD,POST' only — every real-browser PATCH/PUT/DELETE request
  // (webhook update/delete, case report delete, Gmail disconnect, etc.)
  // was blocked at the CORS preflight and never reached the API, while
  // fastify.inject()-based tests never exercise CORS at all so this went
  // undetected. Explicit allowlist so a future @fastify/cors bump can't
  // silently narrow this again.
  methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'],
});

// Setup Metrics
server.register(fastifyMetrics, { endpoint: '/metrics' });

server.register(fastifyRateLimit, {
  max: 100,
  timeWindow: '1 minute',
  redis: createRedisConnection(env.REDIS_URL || 'redis://127.0.0.1:6379'),
  keyGenerator: (request) => {
    return request.ip;
  }
});

// Register Auth Plugins
server.register(fastifyJwt, {
  secret: env.JWT_SECRET,
  cookie: {
    cookieName: 'accessToken',
    signed: false,
  },
});
server.register(fastifyCookie);

// Register Custom RBAC/Auth Middleware
server.register(rbacPlugin);

// Register Multipart for File Uploads. This plugin-level `fileSize` is a
// fallback only — on @fastify/multipart 10 / Fastify 5, a route's own
// `request.file({ limits: {...} })` call fully REPLACES these limits for
// that call rather than being capped by them (confirmed via live testing:
// a 26–29MB upload was accepted here despite this 25MB setting, because
// email.routes.ts's /ingest handler passes its own `fileSize: 25*1024*1024`
// — see that file for the actual authoritative ingress limit). Kept in
// sync with the route's limit as defense-in-depth for any future route
// that omits its own per-call limits.
server.register(fastifyMultipart, {
  limits: { fileSize: 25 * 1024 * 1024 },
});

// Health Check
server.get('/health', async () => {
  return { status: 'ok', timestamp: new Date().toISOString() };
});

// Readiness Check
server.get('/readiness', async (request, reply) => {
  try {
    // Check DB connection
    await prisma.$queryRaw`SELECT 1`;
    return { status: 'ready', timestamp: new Date().toISOString() };
  } catch (error) {
    logger.error({ err: error }, 'Readiness check failed');
    return reply.status(503).send({ status: 'unavailable', timestamp: new Date().toISOString() });
  }
});

// Register API Modules
server.register(authRoutes, { prefix: '/api/v1/auth' });
server.register(emailRoutes, { prefix: '/api/v1/emails' });
server.register(caseRoutes, { prefix: '/api/v1/cases' });
server.register(dashboardRoutes, { prefix: '/api/v1/dashboard' });
server.register(alertRoutes, { prefix: '/api/v1/alerts' });
server.register(investigationRoutes, { prefix: '/api/v1/investigations' });
server.register(evidenceRoutes, { prefix: '/api/v1/evidence' });
server.register(integrationRoutes, { prefix: '/api/v1/integrations' });
server.register(webhookRoutes, { prefix: '/api/v1/webhooks' });
server.register(intelligenceRoutes, { prefix: '/api/v1/intelligence' });
server.register(reportRoutes, { prefix: '/api/v1/reports' });
server.register(analyticsRoutes, { prefix: '/api/v1/analytics' });
server.register(auditRoutes, { prefix: '/api/v1/audit-log' });
server.register(membersRoutes, { prefix: '/api/v1/members' });
server.register(settingsRoutes, { prefix: '/api/v1/settings' });
server.register(invitationRoutes, { prefix: '/api/v1/invitations' });

const start = async () => {
  try {
    const port = env.PORT;
    await server.listen({ port, host: '0.0.0.0' });
    logger.info(`CiperScope API running on port ${port}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
};

// Graceful shutdown
process.on('SIGINT', async () => {
  await server.close();
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await server.close();
  await prisma.$disconnect();
  process.exit(0);
});

start();
