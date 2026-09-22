import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyMultipart from '@fastify/multipart';
import emailRoutes from '../email.routes';
import reportRoutes from '../../report/report.routes';
import { prisma } from '@ciperscope/database';
import { createRedisConnection } from '@ciperscope/queue';
import { LocalRawEmailStore } from '@ciperscope/storage';
import { env, defaultRawEmailStoragePath } from '@ciperscope/config';
import crypto from 'crypto';

/**
 * Phase J — POST/GET /:emailId/reports, GET /reports/:reportId(/download).
 * The BullMQ worker itself isn't running under these tests (same convention
 * as ingestion.integration.test.ts — the route only needs to prove it
 * creates/enqueues correctly), so COMPLETED/FAILED report states used to
 * test viewing/downloading are seeded directly into Postgres, exactly as a
 * real worker run would leave them.
 */
describe('Forensic Report API (Integration)', () => {
  let server: FastifyInstance;
  let orgA: string;
  let orgB: string;
  let emailAId: string;
  let userAId: string;
  const store = new LocalRawEmailStore(defaultRawEmailStoragePath);

  beforeAll(async () => {
    server = Fastify();
    server.register(fastifyMultipart);
    server.decorate('authenticate', async (request: { user: { sub: string; orgs: string[] } }) => {
      request.user = { sub: userAId, orgs: [orgA, orgB] };
    });
    server.decorate('requirePermission', () => {
      return async (request: { headers: Record<string, string> }) => {
        if (!request.headers['x-organization-id']) throw new Error('Tenant isolation failed');
      };
    });
    server.register(emailRoutes, { prefix: '/api/v1/emails' });
    server.register(reportRoutes, { prefix: '/api/v1/reports' });

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    userAId = crypto.randomUUID();
    await prisma.organization.createMany({
      data: [{ id: orgA, name: 'Report Test Org A' }, { id: orgB, name: 'Report Test Org B' }],
    });

    const email = await prisma.email.create({
      data: { organizationId: orgA, sha256: crypto.randomBytes(32).toString('hex'), analysisStatus: 'COMPLETED', senderAddress: 'sender@example.com', subject: 'Report test email' },
    });
    emailAId = email.id;

    await server.ready();
  });

  afterAll(async () => {
    await prisma.forensicReport.deleteMany({ where: { emailId: emailAId } });
    await prisma.email.deleteMany({ where: { id: emailAId } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    await server.close();
    const redis = createRedisConnection(env.REDIS_URL || 'redis://127.0.0.1:6379');
    await redis.quit();
  });

  it('POST /:emailId/reports creates a QUEUED report and enqueues generation', async () => {
    const res = await server.inject({
      method: 'POST',
      url: `/api/v1/emails/${emailAId}/reports`,
      headers: { 'x-organization-id': orgA },
    });
    expect(res.statusCode).toBe(202);
    const body = res.json();
    expect(body.status).toBe('QUEUED');
    expect(body.emailId).toBe(emailAId);
    expect(body.organizationId).toBe(orgA);
    // Internal storage key must never be exposed.
    expect(body).not.toHaveProperty('artifactLocation');
  });

  it('idempotent generation — a request while one is already in-flight returns that report, not a duplicate', async () => {
    // Seeded directly (not via the route) so this test's assertions don't
    // depend on how quickly a real worker consumes the enqueued job — it
    // only exercises the route's own P2002-fallback idempotency logic.
    await prisma.forensicReport.deleteMany({ where: { emailId: emailAId } });
    const existing = await prisma.forensicReport.create({
      data: { organizationId: orgA, emailId: emailAId, status: 'QUEUED', reportVersion: '1.0' },
    });

    const res = await server.inject({ method: 'POST', url: `/api/v1/emails/${emailAId}/reports`, headers: { 'x-organization-id': orgA } });
    expect(res.statusCode).toBe(200);
    expect(res.json().id).toBe(existing.id);

    const count = await prisma.forensicReport.count({ where: { emailId: emailAId } });
    expect(count).toBe(1);
  });

  it('concurrent generation requests never create more than one report row for the email (DB-level guard)', async () => {
    await prisma.forensicReport.deleteMany({ where: { emailId: emailAId } });

    const results = await Promise.all(
      Array.from({ length: 5 }, () =>
        server.inject({ method: 'POST', url: `/api/v1/emails/${emailAId}/reports`, headers: { 'x-organization-id': orgA } })
      )
    );
    // Every response — whichever request won the INSERT race and whichever
    // lost to the partial unique index — must reference the same single
    // report row, regardless of how far a real worker has already carried
    // that report's status by the time each request's fallback lookup ran.
    const ids = new Set(results.map((r) => r.json().id));
    expect(ids.size).toBe(1);

    const count = await prisma.forensicReport.count({ where: { emailId: emailAId } });
    expect(count).toBe(1);
  });

  it('GET /:emailId/reports lists reports for the owning organization only', async () => {
    const res = await server.inject({ method: 'GET', url: `/api/v1/emails/${emailAId}/reports`, headers: { 'x-organization-id': orgA } });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(Array.isArray(body.reports)).toBe(true);
    expect(body.reports.length).toBeGreaterThan(0);
  });

  it('tenant isolation — organization B cannot list organization A\'s reports for that email', async () => {
    const res = await server.inject({ method: 'GET', url: `/api/v1/emails/${emailAId}/reports`, headers: { 'x-organization-id': orgB } });
    expect(res.statusCode).toBe(404);
  });

  it('rejects report generation requests with no tenant context', async () => {
    const res = await server.inject({ method: 'POST', url: `/api/v1/emails/${emailAId}/reports` });
    expect(res.statusCode).toBe(500); // mocked requirePermission throws; real RBAC covered elsewhere
  });

  describe('with a COMPLETED report', () => {
    let reportId: string;
    let sha256: string;
    const pdfContent = Buffer.from('%PDF-1.4\n%TEST-FORENSIC-REPORT\n%%EOF');

    beforeAll(async () => {
      const report = await prisma.forensicReport.create({
        data: {
          organizationId: orgA,
          emailId: emailAId,
          status: 'COMPLETED',
          reportVersion: '1.0',
          generatedAt: new Date(),
          requestedById: userAId,
        },
      });
      reportId = report.id;
      sha256 = crypto.createHash('sha256').update(pdfContent).digest('hex');
      const artifactLocation = `reports/${reportId}.pdf`;
      const { Readable } = await import('stream');
      await store.put(artifactLocation, Readable.from(pdfContent));
      await prisma.forensicReport.update({ where: { id: reportId }, data: { artifactLocation, sha256 } });
    });

    afterAll(async () => {
      await store.delete(`reports/${reportId}.pdf`).catch(() => {});
    });

    it('GET /reports/:reportId returns metadata with SHA-256 and version, never the internal storage key', async () => {
      const res = await server.inject({ method: 'GET', url: `/api/v1/reports/${reportId}`, headers: { 'x-organization-id': orgA } });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.status).toBe('COMPLETED');
      expect(body.sha256).toBe(sha256);
      expect(body.reportVersion).toBe('1.0');
      expect(body).not.toHaveProperty('artifactLocation');
    });

    it('GET /reports/:reportId/download streams the exact artifact and its SHA-256 matches', async () => {
      const res = await server.inject({ method: 'GET', url: `/api/v1/reports/${reportId}/download`, headers: { 'x-organization-id': orgA } });
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toBe('application/pdf');
      expect(res.headers['x-report-sha256']).toBe(sha256);
      const downloadedHash = crypto.createHash('sha256').update(res.rawPayload).digest('hex');
      expect(downloadedHash).toBe(sha256);
    });

    it('download authorization — organization B cannot download organization A\'s report', async () => {
      const res = await server.inject({ method: 'GET', url: `/api/v1/reports/${reportId}/download`, headers: { 'x-organization-id': orgB } });
      expect(res.statusCode).toBe(404);
    });

    it('view authorization — organization B cannot view organization A\'s report metadata (IDOR check)', async () => {
      const res = await server.inject({ method: 'GET', url: `/api/v1/reports/${reportId}`, headers: { 'x-organization-id': orgB } });
      expect(res.statusCode).toBe(404);
    });

    it('the downloaded artifact and its metadata response never contain secrets or tokens', async () => {
      const metaRes = await server.inject({ method: 'GET', url: `/api/v1/reports/${reportId}`, headers: { 'x-organization-id': orgA } });
      const dlRes = await server.inject({ method: 'GET', url: `/api/v1/reports/${reportId}/download`, headers: { 'x-organization-id': orgA } });

      const metaText = metaRes.body.toLowerCase();
      const dlText = dlRes.rawPayload.toString('latin1').toLowerCase();
      const forbidden = /accesstoken|refreshtoken|secretencrypted|webhooksecret|authorization: bearer|password/;
      expect(metaText).not.toMatch(forbidden);
      expect(dlText).not.toMatch(forbidden);
    });
  });

  describe('with a FAILED report', () => {
    let failedReportId: string;

    beforeAll(async () => {
      const report = await prisma.forensicReport.create({
        data: {
          organizationId: orgA,
          emailId: emailAId,
          status: 'FAILED',
          reportVersion: '9.0',
          errorMessage: 'Simulated generation failure',
        },
      });
      failedReportId = report.id;
    });

    it('a FAILED report cannot be downloaded and returns a clear conflict, not a crash', async () => {
      const res = await server.inject({ method: 'GET', url: `/api/v1/reports/${failedReportId}/download`, headers: { 'x-organization-id': orgA } });
      expect(res.statusCode).toBe(409);
    });

    it('a FAILED report is still visible via GET with its errorMessage, for the owning tenant', async () => {
      const res = await server.inject({ method: 'GET', url: `/api/v1/reports/${failedReportId}`, headers: { 'x-organization-id': orgA } });
      expect(res.statusCode).toBe(200);
      expect(res.json().status).toBe('FAILED');
      expect(res.json().errorMessage).toBe('Simulated generation failure');
    });

    it('a FAILED report does not block generating a new one for the same email', async () => {
      await prisma.forensicReport.deleteMany({ where: { emailId: emailAId, status: { in: ['QUEUED', 'GENERATING'] } } });
      const res = await server.inject({ method: 'POST', url: `/api/v1/emails/${emailAId}/reports`, headers: { 'x-organization-id': orgA } });
      expect(res.statusCode).toBe(202);
      expect(res.json().status).toBe('QUEUED');
    });
  });

  it('returns 404 for a nonexistent report ID', async () => {
    const res = await server.inject({ method: 'GET', url: `/api/v1/reports/${crypto.randomUUID()}`, headers: { 'x-organization-id': orgA } });
    expect(res.statusCode).toBe(404);
  });

  it('returns 404 (not 500) when the artifact row exists but is COMPLETED with a missing file on disk', async () => {
    const report = await prisma.forensicReport.create({
      data: {
        organizationId: orgA,
        emailId: emailAId,
        status: 'COMPLETED',
        reportVersion: '99.0',
        generatedAt: new Date(),
        artifactLocation: 'reports/does-not-exist.pdf',
        sha256: 'f'.repeat(64),
      },
    });
    const res = await server.inject({ method: 'GET', url: `/api/v1/reports/${report.id}/download`, headers: { 'x-organization-id': orgA } });
    expect(res.statusCode).toBe(404);
  });
});
