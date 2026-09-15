import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyMultipart from '@fastify/multipart';
import emailRoutes from '../email.routes';
import { prisma } from '@ciperscope/database';
import { createRedisConnection } from '@ciperscope/queue';
import { env } from '@ciperscope/config';
import FormData from 'form-data';
import crypto from 'crypto';

describe('Email Ingestion API (Integration)', () => {
  let server: FastifyInstance;
  let testOrgId: string;
  let testUserId: string;

  beforeAll(async () => {
    server = Fastify();
    server.register(fastifyMultipart);
    
    // Mock Authentication and Authorization for tests
    server.decorate('authenticate', async (request: { user: { sub: string, orgs: string[] } }) => {
      request.user = { sub: testUserId, orgs: [testOrgId] };
    });
    server.decorate('requirePermission', () => {
      return async (request: { headers: Record<string, string> }) => {
         // Mock RBAC logic. Use header for org
         if (!request.headers['x-organization-id']) {
           throw new Error('Tenant isolation failed');
         }
      };
    });

    server.register(emailRoutes, { prefix: '/api/v1/emails' });

    // Seed realistic database values
    testOrgId = crypto.randomUUID();
    testUserId = crypto.randomUUID();

    await prisma.organization.create({
      data: { id: testOrgId, name: 'Test Org' }
    });
    
    await server.ready();
  });

  afterAll(async () => {
    await prisma.organization.delete({ where: { id: testOrgId } });
    await server.close();
    // Delete any queue connections hanging
    const redis = createRedisConnection(env.REDIS_URL || 'redis://127.0.0.1:6379');
    await redis.quit();
  });

  it('should ingest a valid .eml file successfully', async () => {
    const form = new FormData();
    const fileContent = 'Subject: Test\n\nBody';
    form.append('file', Buffer.from(fileContent), { filename: 'test.eml', contentType: 'message/rfc822' });

    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/emails/ingest',
      headers: {
        ...form.getHeaders(),
        'x-organization-id': testOrgId,
      },
      payload: form,
    });

    expect(response.statusCode).toBe(202);
    const json = response.json();
    expect(json.message).toBe('Email ingested and queued for processing');
    expect(json.emailId).toBeDefined();

    // Verify DB
    const email = await prisma.email.findUnique({ where: { id: json.emailId } });
    expect(email).toBeDefined();
    expect(email?.organizationId).toBe(testOrgId);
    
    const hash = crypto.createHash('sha256').update(fileContent).digest('hex');
    expect(email?.sha256).toBe(hash);
  });

  it('should reject requests without tenant context', async () => {
    const form = new FormData();
    form.append('file', Buffer.from('test'), { filename: 'test.eml' });

    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/emails/ingest',
      headers: {
        ...form.getHeaders(),
        // missing x-organization-id
      },
      payload: form,
    });

    expect(response.statusCode).toBe(500); // Mock threw Error
  });

  it('should handle duplicate uploads safely and return 200', async () => {
    const form = new FormData();
    const fileContent = 'Subject: Duplicate\n\nBody';
    form.append('file', Buffer.from(fileContent), { filename: 'dup.eml' });

    const res1 = await server.inject({
      method: 'POST',
      url: '/api/v1/emails/ingest',
      headers: { ...form.getHeaders(), 'x-organization-id': testOrgId },
      payload: form,
    });
    expect(res1.statusCode).toBe(202);

    // Create a new stream for the same content
    const form2 = new FormData();
    form2.append('file', Buffer.from(fileContent), { filename: 'dup.eml' });
    
    const res2 = await server.inject({
      method: 'POST',
      url: '/api/v1/emails/ingest',
      headers: { ...form2.getHeaders(), 'x-organization-id': testOrgId },
      payload: form2,
    });
    
    expect(res2.statusCode).toBe(200);
    expect(res2.json().duplicate).toBe(true);
    expect(res2.json().emailId).toBe(res1.json().emailId);
  });

  it('should reject empty files', async () => {
    const form = new FormData();
    form.append('file', Buffer.from(''), { filename: 'empty.eml' });

    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/emails/ingest',
      headers: {
        ...form.getHeaders(),
        'x-organization-id': testOrgId,
      },
      payload: form,
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().message).toBe('Empty file uploaded');
  });

  it('should respect upload size limits (mock large file)', async () => {
    // Generate an oversized buffer
    const largeBuffer = Buffer.alloc(31 * 1024 * 1024, 'a'); // 31MB
    const form = new FormData();
    form.append('file', largeBuffer, { filename: 'large.eml' });

    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/emails/ingest',
      headers: {
        ...form.getHeaders(),
        'x-organization-id': testOrgId,
      },
      payload: form,
    });

    expect(response.statusCode).toBe(413);
    expect(response.json().message).toBe('Upload limits exceeded');
  });
});
