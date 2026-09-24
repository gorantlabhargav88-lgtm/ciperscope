import { describe, it, expect } from 'vitest';
import Fastify from 'fastify';
import fastifyCors from '@fastify/cors';

/**
 * Regression test for a real, previously-shipped bug: @fastify/cors 9→11
 * (this session's Fastify 5 migration) silently changed its default
 * `methods` option from allowing everything to 'GET,HEAD,POST' only. Every
 * real-browser PATCH/PUT/DELETE request (webhook update/delete, case
 * report delete, Gmail disconnect, case/investigation/alert updates, etc.)
 * was silently blocked at the CORS preflight and never reached the API —
 * found via live E2E (a case report Delete button producing
 * net::ERR_FAILED in the browser), invisible to every existing test
 * because fastify.inject() bypasses CORS entirely. Mirrors the exact
 * options object services/api/src/index.ts registers.
 */
describe('CORS preflight (regression)', () => {
  it('allows PATCH, PUT, and DELETE — not just GET/HEAD/POST', async () => {
    const server = Fastify();
    server.register(fastifyCors, {
      origin: 'http://localhost:5173',
      credentials: true,
      methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'],
    });
    server.delete('/api/v1/webhooks/:id', async () => ({ ok: true }));
    await server.ready();

    const res = await server.inject({
      method: 'OPTIONS',
      url: '/api/v1/webhooks/123',
      headers: {
        origin: 'http://localhost:5173',
        'access-control-request-method': 'DELETE',
      },
    });

    expect(res.statusCode).toBe(204);
    const allowedMethods = (res.headers['access-control-allow-methods'] as string) ?? '';
    expect(allowedMethods).toContain('DELETE');
    expect(allowedMethods).toContain('PATCH');
    expect(allowedMethods).toContain('PUT');

    await server.close();
  });
});
