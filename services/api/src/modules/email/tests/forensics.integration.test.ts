import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import emailRoutes from '../email.routes';
import { prisma } from '@ciperscope/database';
import { env } from '@ciperscope/config';
import crypto from 'crypto';

describe('Email Forensics API (Integration)', () => {
  let server: FastifyInstance;
  let testOrgId: string;
  let testUserId: string;
  let otherOrgId: string;
  let testEmailId: string;
  let otherEmailId: string;

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

    testOrgId = crypto.randomUUID();
    testUserId = crypto.randomUUID();
    otherOrgId = crypto.randomUUID();

    await prisma.organization.createMany({
      data: [
        { id: testOrgId, name: 'Test Org' },
        { id: otherOrgId, name: 'Other Org' }
      ]
    });

    const email = await prisma.email.create({
      data: {
        organizationId: testOrgId,
        sha256: crypto.randomUUID(),
        subject: 'Test Forensics',
        ingestionSrc: 'TEST'
      }
    });
    testEmailId = email.id;

    const otherEmail = await prisma.email.create({
      data: {
        organizationId: otherOrgId,
        sha256: crypto.randomUUID(),
        subject: 'Other Forensics',
        ingestionSrc: 'TEST'
      }
    });
    otherEmailId = otherEmail.id;

    // Seed Indicator and ThreatIntelObservation
    const randomDomain = `malicious-${crypto.randomUUID()}.com`;
    const randomIp = `1.2.3.${Math.floor(Math.random() * 255)}`;
    const indicator = await prisma.indicator.create({
      data: {
        type: 'DOMAIN',
        value: randomDomain
      }
    });

    await prisma.threatIntelObservation.create({
      data: {
        indicatorId: indicator.id,
        provider: 'TestProvider',
        verdict: 'MALICIOUS',
        confidence: 90,
        rawResponse: { secret: 'do-not-expose' }
      }
    });

    // Link indicator to email via Url
    await prisma.emailUrl.create({
      data: {
        emailId: testEmailId,
        url: `http://${randomDomain}`
      }
    });

    // Seed Geolocation
    await prisma.geoLocation.create({
      data: {
        ipAddress: randomIp,
        country: 'US',
        city: 'Seattle',
        asn: 'AS1234',
        isp: 'Test ISP'
      }
    });

    // Link IP to email via RelayHop
    await prisma.relayHop.create({
      data: {
        emailId: testEmailId,
        hopOrder: 0,
        sourceIp: randomIp,
        receivedHeader: 'from [1.2.3.4]'
      }
    });

    server.decorate('testData', { randomDomain, randomIp });

    await server.ready();
  });

  afterAll(async () => {
    await prisma.organization.deleteMany({
      where: { id: { in: [testOrgId, otherOrgId] } }
    });
    await server.close();
  });

  // Threat Indicators Tests
  it('should return ThreatIndicator records for authorized tenant', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${testEmailId}/threat-indicators`,
      headers: {
        'x-organization-id': testOrgId,
      },
    });

    expect(response.statusCode).toBe(200);
    const json = response.json();
    expect(json.threatIndicators).toBeDefined();
    expect(json.threatIndicators).toHaveLength(1);

    const indicator = json.threatIndicators[0];
    const { randomDomain } = (server as any).testData;
    expect(indicator.iocType).toBe('DOMAIN');
    expect(indicator.iocValue).toBe(randomDomain);
    expect(indicator.provider).toBe('TestProvider');
    expect(indicator.status).toBe('MALICIOUS');
    expect(indicator.confidence).toBe(90);
    // Ensure metadata is NOT exposed
    expect(indicator.metadata).toBeUndefined();
    expect(indicator.rawResponse).toBeUndefined();
  });

  it('should return empty ThreatIndicator array for email with no records', async () => {
    // Create another email with no indicators
    const emptyEmail = await prisma.email.create({
      data: {
        organizationId: testOrgId,
        sha256: crypto.randomUUID(),
        subject: 'Empty',
        ingestionSrc: 'TEST'
      }
    });

    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emptyEmail.id}/threat-indicators`,
      headers: {
        'x-organization-id': testOrgId,
      },
    });

    expect(response.statusCode).toBe(200);
    const json = response.json();
    expect(json.threatIndicators).toEqual([]);
  });

  it('should deny cross-tenant ThreatIndicator access with 404', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${otherEmailId}/threat-indicators`,
      headers: {
        'x-organization-id': testOrgId, // Using testOrgId for otherOrgId's email
      },
    });

    expect(response.statusCode).toBe(404);
  });

  it('should reject unauthenticated ThreatIndicator request', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${testEmailId}/threat-indicators`,
      // Missing x-organization-id
    });

    expect(response.statusCode).toBe(500); // Mock threw Error
  });

  it('should return 404 for nonexistent email on ThreatIndicator request', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/00000000-0000-0000-0000-000000000000/threat-indicators`,
      headers: {
        'x-organization-id': testOrgId,
      },
    });

    expect(response.statusCode).toBe(404);
  });

  // Geolocation Tests
  it('should return Geolocation records for authorized tenant', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${testEmailId}/geolocation`,
      headers: {
        'x-organization-id': testOrgId,
      },
    });

    expect(response.statusCode).toBe(200);
    const json = response.json();
    expect(json.geolocation).toBeDefined();
    expect(json.geolocation).toHaveLength(1);

    const geo = json.geolocation[0];
    const { randomIp } = (server as any).testData;
    expect(geo.ipAddress).toBe(randomIp);
    expect(geo.country).toBe('US');
    expect(geo.city).toBe('Seattle');
    expect(geo.asn).toBe('AS1234');
    expect(geo.isp).toBe('Test ISP');
  });

  it('should return empty Geolocation array for email with no records', async () => {
    const emptyEmail = await prisma.email.create({
      data: {
        organizationId: testOrgId,
        sha256: crypto.randomUUID(),
        subject: 'Empty Geo',
        ingestionSrc: 'TEST'
      }
    });

    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${emptyEmail.id}/geolocation`,
      headers: {
        'x-organization-id': testOrgId,
      },
    });

    expect(response.statusCode).toBe(200);
    const json = response.json();
    expect(json.geolocation).toEqual([]);
  });

  it('should deny cross-tenant Geolocation access with 404', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${otherEmailId}/geolocation`,
      headers: {
        'x-organization-id': testOrgId,
      },
    });

    expect(response.statusCode).toBe(404);
  });

  it('should reject unauthenticated Geolocation request', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/${testEmailId}/geolocation`,
    });

    expect(response.statusCode).toBe(500); // Mock threw Error
  });

  it('should return 404 for nonexistent email on Geolocation request', async () => {
    const response = await server.inject({
      method: 'GET',
      url: `/api/v1/emails/00000000-0000-0000-0000-000000000000/geolocation`,
      headers: {
        'x-organization-id': testOrgId,
      },
    });

    expect(response.statusCode).toBe(404);
  });
});
