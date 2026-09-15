import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import fastifyCookie from '@fastify/cookie';
import fastifyCors from '@fastify/cors';
import fastifyHelmet from '@fastify/helmet';
import fastifyRateLimit from '@fastify/rate-limit';
import { prisma } from '@ciperscope/database';
import authRoutes from './modules/auth/auth.routes';
import rbacPlugin from './plugins/rbac';
import emailRoutes from './modules/email/email.routes';
import fastifyMultipart from '@fastify/multipart';
import { createRedisConnection } from '@ciperscope/queue';

import { logger, loggerOptions, generateRequestId, runWithContext } from '@ciperscope/logger';
import { env } from '@ciperscope/config';

const server: FastifyInstance = Fastify({
  logger: loggerOptions,
  genReqId: () => generateRequestId(),
  // Prevent X-Forwarded-For spoofing by only trusting explicitly configured proxies
  trustProxy: env.TRUST_PROXY ? env.TRUST_PROXY.split(',') : false,
});

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
server.setErrorHandler((error, request, reply) => {
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

// Register Multipart for File Uploads
server.register(fastifyMultipart);

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
