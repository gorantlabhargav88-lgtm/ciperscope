import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify from 'fastify';
import authRoutes from '../../src/modules/auth/auth.routes';

describe('HTTP Body Validation', () => {
  const server = Fastify();

  // Mock authenticate hook to bypass JWT verification for testing validation
  server.decorate('authenticate', async () => {});

  beforeAll(async () => {
    server.register(authRoutes, { prefix: '/auth' });
    await server.ready();
  });

  afterAll(async () => {
    await server.close();
  });

  describe('Login Route (/auth/login)', () => {
    it('rejects missing email', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { password: 'password123' },
      });
      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.payload).message).toContain("body must have required property 'email'");
    });

    it('rejects missing password', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'test@example.com' },
      });
      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.payload).message).toContain("body must have required property 'password'");
    });

    it('rejects invalid email format', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'not-an-email', password: 'password123' },
      });
      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.payload).message).toContain('email must match format "email"');
    });

    it('rejects short passwords', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'test@example.com', password: 'short' },
      });
      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.payload).message).toContain('password must NOT have fewer than 8 characters');
    });

    it('rejects oversized email', async () => {
      const oversizedEmail = 'a'.repeat(250) + '@example.com';
      const response = await server.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: oversizedEmail, password: 'password123' },
      });
      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.payload).message).toContain('email must NOT have more than 255 characters');
    });

    it('rejects oversized password', async () => {
      const oversizedPassword = 'p'.repeat(1025);
      const response = await server.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'test@example.com', password: oversizedPassword },
      });
      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.payload).message).toContain('password must NOT have more than 1024 characters');
    });

    it('rejects array instead of object', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/auth/login',
        payload: [{ email: 'test@example.com', password: 'password123' }],
      });
      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.payload).message).toContain('body must be object');
    });

    it('rejects null', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/auth/login',
        payload: null,
      });
      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.payload).message).toContain('body must be object');
    });
  });

  describe('Refresh Route (/auth/refresh)', () => {
    it('rejects missing refreshToken', async () => {
      const response = await server.inject({
        method: 'POST',
        url: '/auth/refresh',
        payload: {},
      });
      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.payload).message).toContain("body must have required property 'refreshToken'");
    });

    it('rejects oversized token', async () => {
      const oversizedToken = 'a'.repeat(1025);
      const response = await server.inject({
        method: 'POST',
        url: '/auth/refresh',
        payload: { refreshToken: oversizedToken },
      });
      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.payload).message).toContain('refreshToken must NOT have more than 1024 characters');
    });
  });
});
