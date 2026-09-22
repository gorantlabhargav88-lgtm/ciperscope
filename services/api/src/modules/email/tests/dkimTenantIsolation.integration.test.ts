import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import emailRoutes from '../email.routes';
import { prisma } from '@ciperscope/database';
import crypto from 'crypto';

/**
 * Phase 10C.1 — DKIM12: traces and exercises the REAL DKIM API surface
 * (GET /api/v1/emails/:emailId/dkim in services/api/src/modules/email/email.routes.ts),
 * following the exact fixture/mock conventions already established in
 * forensics.integration.test.ts for this same route file (a real Postgres-backed
 * Fastify instance with `authenticate`/`requirePermission` decorated as minimal
 * stand-ins, since email.routes.ts enforces tenant isolation itself via
 * `prisma.email.findUnique({ where: { id, organizationId } })` rather than via
 * the RBAC plugin used elsewhere).
 */
describe('DKIM API — tenant isolation (Integration)', () => {
  let server: FastifyInstance;
  let orgAId: string;
  let orgBId: string;
  let testUserId: string;
  let emailAId: string;
  let dkimVerificationAId: string;

  beforeAll(async () => {
    server = Fastify();

    server.decorate('authenticate', async (request: { user: { sub: string } }) => {
      request.user = { sub: testUserId };
    });
    server.decorate('requirePermission', () => {
      return async (request: { headers: Record<string, string> }) => {
        if (!request.headers['x-organization-id']) {
          throw new Error('Tenant isolation failed');
        }
      };
    });

    server.register(emailRoutes, { prefix: '/api/v1/emails' });

    orgAId = crypto.randomUUID();
    orgBId = crypto.randomUUID();
    testUserId = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [
        { id: orgAId, name: 'DKIM Tenant Isolation Org A' },
        { id: orgBId, name: 'DKIM Tenant Isolation Org B' }
      ]
    });

    // Org A owns an email with a real, persisted DKIM verification result —
    // the exact shape AuthenticationVerifier.verifyEmail() writes.
    const emailA = await prisma.email.create({
      data: {
        organizationId: orgAId,
        sha256: crypto.randomUUID(),
        subject: 'DKIM Tenant Isolation Test',
        ingestionSrc: 'TEST'
      }
    });
    emailAId = emailA.id;

    const dkimVerificationA = await prisma.dkimVerification.create({
      data: {
        emailId: emailAId,
        result: 'PASS',
        domain: 'org-a-sender.example',
        selector: 'sel1',
        algorithm: 'rsa-sha256',
        bodyHashResult: 'PASS',
        explanation: 'Signature cryptographically verified using key at sel1._domainkey.org-a-sender.example'
      }
    });
    dkimVerificationAId = dkimVerificationA.id;

    await server.ready();
  });

  afterAll(async () => {
    await prisma.dkimVerification.deleteMany({ where: { emailId: emailAId } });
    await prisma.email.deleteMany({ where: { organizationId: { in: [orgAId, orgBId] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgAId, orgBId] } } });
    await server.close();
  });

  it('DKIM12-1/2: Org A can retrieve its own persisted DKIM result via GET /:emailId/dkim', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailAId}/dkim`,
      headers: { 'x-organization-id': orgAId }
    });

    expect(response.statusCode).toBe(200);
    const json = response.json();
    expect(json.dkimVerifications).toHaveLength(1);
    expect(json.dkimVerifications[0].id).toBe(dkimVerificationAId);
    expect(json.dkimVerifications[0].result).toBe('PASS');
    expect(json.dkimVerifications[0].domain).toBe('org-a-sender.example');
  });

  it('DKIM12-3/5: Org B, otherwise validly authenticated, cannot retrieve Org A\'s DKIM result — 404, and no Org A data leaks into the response', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailAId}/dkim`,
      headers: { 'x-organization-id': orgBId } // Org B's own org context, targeting Org A's emailId
    });

    expect(response.statusCode).toBe(404);
    const body = response.body;
    expect(body).not.toContain(dkimVerificationAId);
    expect(body).not.toContain('org-a-sender.example');
    expect(body).not.toContain('PASS');
  });

  it('DKIM12-4: a nonexistent email ID returns 404, matching the existing API convention (same as threat-indicators/geolocation)', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${crypto.randomUUID()}/dkim`,
      headers: { 'x-organization-id': orgAId }
    });

    expect(response.statusCode).toBe(404);
  });

  it('rejects a request with no organization context (tenant isolation cannot be bypassed by omitting the header)', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailAId}/dkim`
      // Missing x-organization-id
    });

    // Matches the existing convention in forensics.integration.test.ts for this
    // same route file: the test-decorated requirePermission mock throws a plain
    // Error (no custom Fastify error handler registered in this minimal test
    // server), which Fastify surfaces as 500 — not the production error handler's
    // shape, which is not under test here.
    expect(response.statusCode).toBe(500);
  });

  it('Org B querying its own (nonexistent) email for DKIM data gets an empty result, never Org A\'s row', async () => {
    const emailB = await prisma.email.create({
      data: {
        organizationId: orgBId,
        sha256: crypto.randomUUID(),
        subject: 'Org B email with no DKIM data',
        ingestionSrc: 'TEST'
      }
    });

    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emailB.id}/dkim`,
      headers: { 'x-organization-id': orgBId }
    });

    expect(response.statusCode).toBe(200);
    const json = response.json();
    expect(json.dkimVerifications).toEqual([]);

    await prisma.email.deleteMany({ where: { id: emailB.id } });
  });
});
