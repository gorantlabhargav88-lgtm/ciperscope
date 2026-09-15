import { FastifyInstance } from 'fastify';
import { loginHandler, logoutHandler, refreshHandler, meHandler } from './auth.controller';
import { multiRateLimit } from '../../middleware/rateLimiter';

// JSON schemas for validation
const LoginSchema = {
  type: 'object',
  required: ['email', 'password'],
  properties: {
    email: { type: 'string', format: 'email' },
    password: { type: 'string', minLength: 8 },
  },
};

const RefreshSchema = {
  type: 'object',
  required: ['refreshToken'],
  properties: {
    refreshToken: { type: 'string' },
  },
};

export default async function authRoutes(fastify: FastifyInstance) {
  fastify.post('/login', {
    schema: {
      body: LoginSchema,
    },
    preHandler: multiRateLimit([
      // IP limit: 10 attempts per minute. Fail closed to prevent distributed brute force.
      (req) => ({ key: `rl:auth:ip:${req.ip}`, max: 10, windowSec: 60, failOpen: false, errorMessage: 'Too many login attempts from this IP' }),
      // Account limit: 5 attempts per minute. Prevent brute forcing a specific user.
      (req) => ({ key: `rl:auth:user:${(req.body as any).email}`, max: 5, windowSec: 60, failOpen: false, errorMessage: 'Too many login attempts for this account' })
    ]),
    handler: loginHandler(fastify),
  });

  fastify.post('/refresh', {
    schema: {
      body: RefreshSchema,
    },
    preHandler: multiRateLimit([
      // Token refresh is less critical but still needs protection from rapid token-generation exhaustion
      (req) => ({ key: `rl:refresh:ip:${req.ip}`, max: 30, windowSec: 60, failOpen: false, errorMessage: 'Too many refresh attempts' })
    ]),
    handler: refreshHandler(fastify),
  });

  fastify.post('/logout', {
    preValidation: [fastify.authenticate],
    handler: logoutHandler,
  });

  fastify.get('/me', {
    preValidation: [fastify.authenticate],
    handler: meHandler,
  });
}
