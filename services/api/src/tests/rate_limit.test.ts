import { describe, it, expect } from 'vitest';
import Fastify from 'fastify';
import fastifyRateLimit from '@fastify/rate-limit';

describe('Rate Limit Config', () => {
  it('should generate key based on request.ip, ignoring x-organization-id', async () => {
    const server = Fastify();
    await server.register(fastifyRateLimit, {
      max: 1000,
      timeWindow: '1 minute',
      keyGenerator: (request) => {
        return request.ip;
      }
    });

    server.get('/', async () => 'ok');
    await server.ready();

    // Request from IP 127.0.0.1 (default in Fastify inject) with org-1
    const response1 = await server.inject({
      method: 'GET',
      url: '/',
      headers: { 'x-organization-id': 'org-1' }
    });

    // Request from SAME IP 127.0.0.1 with org-2
    const response2 = await server.inject({
      method: 'GET',
      url: '/',
      headers: { 'x-organization-id': 'org-2' }
    });

    expect(response1.statusCode).toBe(200);
    expect(response2.statusCode).toBe(200);
    expect(response1.headers['x-ratelimit-remaining']).toBe('999');
    expect(response2.headers['x-ratelimit-remaining']).toBe('998'); // Same bucket used
  });
});
