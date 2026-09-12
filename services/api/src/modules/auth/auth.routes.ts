import { FastifyInstance } from 'fastify';
import { loginHandler, logoutHandler, refreshHandler, meHandler } from './auth.controller';
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
    handler: loginHandler(fastify),
  });

  fastify.post('/refresh', {
    schema: {
      body: RefreshSchema,
    },
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
