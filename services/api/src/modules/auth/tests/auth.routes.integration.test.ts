import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import fastifyCookie from '@fastify/cookie';
import crypto from 'crypto';
import { prisma } from '@ciperscope/database';
import { hashPassword } from '../../../utils/crypto';
import rbacPlugin from '../../../plugins/rbac';
import tolerantJsonBodyParser from '../../../plugins/tolerantJsonBodyParser';
import authRoutes from '../auth.routes';

/**
 * Real login → logout session lifecycle against a real Postgres, with the
 * exact fastifyJwt + cookie configuration services/api/src/index.ts uses.
 *
 * This exists because a real regression shipped and went undetected: the
 * frontend api clients (apps/web/src/lib/api.ts, packages/api-client)
 * always sent `Content-Type: application/json` even on body-less POSTs
 * (e.g. /auth/logout), and Fastify 5's stricter body parser rejects that
 * combination with FST_ERR_CTP_EMPTY_JSON_BODY — so logout returned 500 for
 * every real browser session while still passing CI, because
 * bodyValidation.test.ts's server.inject() calls never set that header on
 * a body-less request. Found via live E2E against the running dev server
 * (browser DevTools showed a 500 on /auth/logout), fixed in both frontend
 * clients, and locked in here against the real header a browser sends.
 */
describe('Auth session lifecycle API (Integration)', () => {
  let server: FastifyInstance;
  let orgId: string;
  let userId: string;
  const password = 'correct-horse-battery-staple';

  beforeAll(async () => {
    server = Fastify();
    server.register(tolerantJsonBodyParser);
    server.register(fastifyJwt, { secret: 'test-auth-lifecycle-secret', cookie: { cookieName: 'accessToken', signed: false } });
    server.register(fastifyCookie);
    server.register(rbacPlugin);
    server.register(authRoutes, { prefix: '/api/v1/auth' });
    await server.ready();

    orgId = crypto.randomUUID();
    userId = crypto.randomUUID();

    await prisma.organization.create({ data: { id: orgId, name: 'Auth Lifecycle Test Org' } });
    await prisma.user.create({
      data: {
        id: userId,
        email: `auth-lifecycle-${Date.now()}@test.local`,
        passwordHash: await hashPassword(password),
        isActive: true,
      },
    });
  });

  afterAll(async () => {
    await prisma.refreshToken.deleteMany({ where: { session: { userId } } });
    await prisma.session.deleteMany({ where: { userId } });
    await prisma.user.deleteMany({ where: { id: userId } });
    await prisma.organization.deleteMany({ where: { id: orgId } });
    await server.close();
  });

  it('logs in, then logs out with the exact headers a real browser sends (Content-Type set, empty body) — never FST_ERR_CTP_EMPTY_JSON_BODY', async () => {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });

    const loginRes = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: user.email, password },
    });
    expect(loginRes.statusCode).toBe(200);
    const accessToken = loginRes.json().accessToken;
    expect(accessToken).toBeTruthy();

    // Reproduces apps/web/src/lib/api.ts's real fetch() call: explicit
    // Content-Type header, genuinely empty body — this exact combination
    // is what triggered the regression.
    const logoutRes = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/logout',
      headers: {
        authorization: `Bearer ${accessToken}`,
        'content-type': 'application/json',
      },
    });

    expect(logoutRes.statusCode).toBe(200);
    expect(logoutRes.json().message).toBe('Logged out successfully');
  });

  it('rejects logout without authentication', async () => {
    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/logout',
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(401);
  });

  it('a session revoked by logout can no longer authenticate', async () => {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });

    const loginRes = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: user.email, password },
    });
    const accessToken = loginRes.json().accessToken;

    const logoutRes = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/logout',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(logoutRes.statusCode).toBe(200);

    const meRes = await server.inject({
      method: 'GET',
      url: '/api/v1/auth/me',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(meRes.statusCode).toBe(401);
  });
});
