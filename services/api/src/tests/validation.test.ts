import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify from 'fastify';
import { uuidSchema } from '../../src/utils/validation';
import { fastifyEmailParamsSchema, fastifyAttachmentParamsSchema } from '../../src/utils/validation';

describe('Central Validation', () => {
  it('uuidSchema rejects malformed UUIDs', () => {
    expect(uuidSchema.safeParse('not-a-uuid').success).toBe(false);
    expect(uuidSchema.safeParse('12345678-1234-1234-1234-1234567890ab; DROP TABLE emails;').success).toBe(false);
    expect(uuidSchema.safeParse('../../../etc/passwd').success).toBe(false);
    expect(uuidSchema.safeParse('').success).toBe(false);
    expect(uuidSchema.safeParse(null).success).toBe(false);
  });

  it('uuidSchema accepts valid UUIDs', () => {
    expect(uuidSchema.safeParse('123e4567-e89b-12d3-a456-426614174000').success).toBe(true);
  });
});

describe('Fastify Route Validation', () => {
  const server = Fastify();
  let handlerCalled = false;

  beforeAll(async () => {
    server.get('/test/email/:emailId', {
      schema: { params: fastifyEmailParamsSchema }
    }, async (request, reply) => {
      handlerCalled = true;
      return { success: true };
    });

    server.get('/test/attachment/:emailId/:attachmentId', {
      schema: { params: fastifyAttachmentParamsSchema }
    }, async (request, reply) => {
      handlerCalled = true;
      return { success: true };
    });

    await server.ready();
  });

  afterAll(async () => {
    await server.close();
  });

  it('rejects malformed emailId before handler', async () => {
    handlerCalled = false;
    const response = await server.inject({
      method: 'GET',
      url: '/test/email/not-a-uuid'
    });
    
    expect(response.statusCode).toBe(400);
    expect(handlerCalled).toBe(false);
    expect(JSON.parse(response.payload).message).toContain('emailId must match format "uuid"');
  });

  it('rejects malformed attachmentId before handler', async () => {
    handlerCalled = false;
    const response = await server.inject({
      method: 'GET',
      url: '/test/attachment/123e4567-e89b-12d3-a456-426614174000/malformed-id'
    });
    
    expect(response.statusCode).toBe(400);
    expect(handlerCalled).toBe(false);
  });

  it('accepts valid UUIDs in path', async () => {
    handlerCalled = false;
    const response = await server.inject({
      method: 'GET',
      url: '/test/attachment/123e4567-e89b-12d3-a456-426614174000/123e4567-e89b-12d3-a456-426614174001'
    });
    
    expect(response.statusCode).toBe(200);
    expect(handlerCalled).toBe(true);
  });
});
