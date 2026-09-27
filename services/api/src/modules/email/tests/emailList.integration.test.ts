import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import emailRoutes from '../email.routes';
import { prisma } from '@ciperscope/database';
import crypto from 'crypto';

describe('Email List API (Integration)', () => {
  let server: FastifyInstance;
  let testOrgId: string;
  let testUserId: string;
  let otherOrgId: string;
  let email1Id: string;
  let email2Id: string;
  let otherEmailId: string;

  beforeAll(async () => {
    server = Fastify();

    server.decorate('authenticate', async (request: { user: { sub: string; orgs: string[] } }) => {
      request.user = { sub: testUserId, orgs: [testOrgId, otherOrgId] };
    });
    server.decorate('requirePermission', () => {
      return async (request: { headers: Record<string, string> }) => {
        if (!request.headers['x-organization-id']) {
          const err = new Error('Tenant header missing') as any;
          err.statusCode = 400;
          throw err;
        }
      };
    });

    server.register(emailRoutes, { prefix: '/api/v1/emails' });
    await server.ready();

    testOrgId = crypto.randomUUID();
    testUserId = crypto.randomUUID();
    otherOrgId = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [
        { id: testOrgId, name: 'Test Org List' },
        { id: otherOrgId, name: 'Other Org List' },
      ],
    });

    // Seed email 1 for testOrg (Gmail ingestion, phishing, P1)
    const email1 = await prisma.email.create({
      data: {
        organizationId: testOrgId,
        sha256: crypto.randomUUID(),
        subject: 'Invoice payment request',
        senderAddress: 'finance@suspicious-bank.com',
        analysisStatus: 'COMPLETED',
        classification: 'PHISHING',
        ingestionSrc: 'GMAIL',
        date: new Date(Date.now() - 60000),
        addresses: {
          create: [
            {
              headerName: 'to',
              raw: 'victim@myorg.com',
              address: 'victim@myorg.com',
            },
          ],
        },
      },
    });
    email1Id = email1.id;

    // Attach risk assessment
    await prisma.riskAssessment.create({
      data: {
        emailId: email1Id,
        overallScore: 88,
        riskLevel: 'HIGH',
        version: '1.0',
      },
    });

    // Add attachments
    await prisma.emailAttachment.create({
      data: {
        emailId: email1Id,
        filename: 'invoice.pdf',
        mimeType: 'application/pdf',
        sizeBytes: 1024,
        sha256: crypto.randomUUID(),
      },
    });

    // Seed email 2 for testOrg (Legitimate, manual upload)
    const email2 = await prisma.email.create({
      data: {
        organizationId: testOrgId,
        sha256: crypto.randomUUID(),
        subject: 'Team meeting agenda',
        senderAddress: 'boss@myorg.com',
        analysisStatus: 'COMPLETED',
        classification: 'LEGITIMATE',
        ingestionSrc: 'MANUAL_UPLOAD',
        date: new Date(Date.now()),
        addresses: {
          create: [
            {
              headerName: 'to',
              raw: 'all@myorg.com',
              address: 'all@myorg.com',
            },
          ],
        },
      },
    });
    email2Id = email2.id;

    // Seed email for otherOrg (Tenant isolation check)
    const otherEmail = await prisma.email.create({
      data: {
        organizationId: otherOrgId,
        sha256: crypto.randomUUID(),
        subject: 'Confidential other org memo',
        senderAddress: 'secret@other.com',
        analysisStatus: 'COMPLETED',
        ingestionSrc: 'GMAIL',
      },
    });
    otherEmailId = otherEmail.id;
  });

  afterAll(async () => {
    const ids = [email1Id, email2Id, otherEmailId].filter(Boolean);
    await prisma.emailAttachment.deleteMany({ where: { emailId: { in: ids } } });
    await prisma.riskAssessment.deleteMany({ where: { emailId: { in: ids } } });
    await prisma.emailAddress.deleteMany({ where: { emailId: { in: ids } } });
    await prisma.email.deleteMany({ where: { id: { in: ids } } });
    await prisma.organization.deleteMany({ where: { id: { in: [testOrgId, otherOrgId].filter(Boolean) } } });
    await server.close();
  });

  it('should list emails for authenticated organization with newest first', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/emails?page=1&limit=10',
      headers: { 'x-organization-id': testOrgId },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items).toBeDefined();
    expect(body.total).toBe(2);
    expect(body.items.length).toBe(2);

    // Newest first: email2 (newer date) should be first
    expect(body.items[0].id).toBe(email2Id);
    expect(body.items[0].subject).toBe('Team meeting agenda');
    expect(body.items[0].sender).toBe('boss@myorg.com');
    expect(body.items[0].classification).toBe('LEGITIMATE');

    // Email 1 has P1, risk score 88, 1 attachment
    expect(body.items[1].id).toBe(email1Id);
    expect(body.items[1].subject).toBe('Invoice payment request');
    expect(body.items[1].sender).toBe('finance@suspicious-bank.com');
    expect(body.items[1].recipient).toBe('victim@myorg.com');
    expect(body.items[1].classification).toBe('PHISHING');
    expect(body.items[1].riskScore).toBe(88);
    expect(body.items[1].priority).toBe('P1');
    expect(body.items[1].attachmentCount).toBe(1);
    expect(body.items[1].isSuspiciousOrMalicious).toBe(true);
    expect(body.items[1].ingestionSrc).toBe('GMAIL');
  });

  it('should filter by search keyword (subject / sender / recipient)', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/emails?search=invoice',
      headers: { 'x-organization-id': testOrgId },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.total).toBe(1);
    expect(body.items[0].id).toBe(email1Id);
  });

  it('should filter by classification', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/emails?classification=PHISHING',
      headers: { 'x-organization-id': testOrgId },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.total).toBe(1);
    expect(body.items[0].id).toBe(email1Id);
  });

  it('should filter by source (e.g. GMAIL)', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/emails?source=GMAIL',
      headers: { 'x-organization-id': testOrgId },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.total).toBe(1);
    expect(body.items[0].id).toBe(email1Id);
    expect(body.items[0].ingestionSrc).toBe('GMAIL');
  });

  it('should strictly isolate tenants (never return emails from other organizations)', async () => {
    const res = await server.inject({
      method: 'GET',
      url: '/api/v1/emails',
      headers: { 'x-organization-id': otherOrgId },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.total).toBe(1);
    expect(body.items[0].id).toBe(otherEmailId);
    expect(body.items.some((i: any) => i.id === email1Id || i.id === email2Id)).toBe(false);
  });
});
