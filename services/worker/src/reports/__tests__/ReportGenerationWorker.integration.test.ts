import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import path from 'path';
import os from 'os';
import fs from 'fs';
import crypto from 'crypto';
// Triggers @ciperscope/config's dotenv.config() load of the repo-root .env
// (for DATABASE_URL) before @ciperscope/database's PrismaClient is
// constructed below — see packages/config/src/index.ts.
import '@ciperscope/config';
import { prisma } from '@ciperscope/database';
import { LocalRawEmailStore } from '@ciperscope/storage';
import { ReportGenerationWorker, reportArtifactKey } from '../ReportGenerationWorker';

/**
 * Real-Postgres integration test for the worker's report generation
 * pipeline: collectReportInput -> buildReportData -> renderReportPdf ->
 * hash -> persist artifact -> update ForensicReport row. Uses a scratch
 * local storage directory (never the real .data/emails path) so it never
 * collides with dev data.
 */
describe('ReportGenerationWorker (Integration)', () => {
  let orgA: string;
  let orgB: string;
  let emailAId: string;
  let store: LocalRawEmailStore;
  let worker: ReportGenerationWorker;
  let scratchDir: string;

  beforeAll(async () => {
    scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ciperscope-report-test-'));
    store = new LocalRawEmailStore(scratchDir);
    worker = new ReportGenerationWorker(prisma, store);

    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    await prisma.organization.createMany({
      data: [{ id: orgA, name: 'Report Worker Test Org A' }, { id: orgB, name: 'Report Worker Test Org B' }],
    });

    const email = await prisma.email.create({
      data: {
        organizationId: orgA,
        sha256: crypto.randomBytes(32).toString('hex'),
        analysisStatus: 'COMPLETED',
        senderAddress: 'attacker@evil.example',
        subject: 'Worker integration test email',
      },
    });
    emailAId = email.id;

    await prisma.relayHop.create({
      data: { emailId: emailAId, hopOrder: 0, sourceIp: '198.51.100.77', receivedHeader: 'from evil (evil [198.51.100.77]) by mx' },
    });
    await prisma.emailUrl.create({
      data: { emailId: emailAId, url: 'https://evil.example/login', domain: 'evil.example', source: 'TEXT', indicators: ['BRAND_IMPERSONATION'] },
    });
    await prisma.emailAttachment.create({
      data: { emailId: emailAId, filename: 'invoice.apk', mimeType: 'application/vnd.android.package-archive', sizeBytes: 2048, sha256: 'c'.repeat(64), apkMetadata: { packageName: 'com.evil.app' } },
    });
    const riskAssessment = await prisma.riskAssessment.create({
      data: { emailId: emailAId, overallScore: 88, riskLevel: 'HIGH', version: '1' },
    });
    await prisma.riskFactor.create({
      data: { riskAssessmentId: riskAssessment.id, category: 'PHISHING_URL', description: 'Lookalike domain', scoreContribution: 88 },
    });
  });

  afterAll(async () => {
    await prisma.riskFactor.deleteMany({ where: { riskAssessment: { emailId: emailAId } } });
    await prisma.riskAssessment.deleteMany({ where: { emailId: emailAId } });
    await prisma.emailAttachment.deleteMany({ where: { emailId: emailAId } });
    await prisma.emailUrl.deleteMany({ where: { emailId: emailAId } });
    await prisma.relayHop.deleteMany({ where: { emailId: emailAId } });
    await prisma.forensicReport.deleteMany({ where: { emailId: emailAId } });
    await prisma.email.deleteMany({ where: { id: emailAId } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
    fs.rmSync(scratchDir, { recursive: true, force: true });
  });

  it('generates a COMPLETED report whose persisted SHA-256 matches the stored artifact bytes', async () => {
    const report = await prisma.forensicReport.create({
      data: { organizationId: orgA, emailId: emailAId, reportVersion: '1.0' },
    });

    await worker.generate(report.id, orgA);

    const updated = await prisma.forensicReport.findUniqueOrThrow({ where: { id: report.id } });
    expect(updated.status).toBe('COMPLETED');
    expect(updated.artifactLocation).toBe(reportArtifactKey(report.id));
    expect(updated.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(updated.generatedAt).not.toBeNull();

    const artifactStream = await store.get(updated.artifactLocation as string);
    const chunks: Buffer[] = [];
    for await (const chunk of artifactStream) chunks.push(chunk as Buffer);
    const artifactBuffer = Buffer.concat(chunks);
    const actualHash = crypto.createHash('sha256').update(artifactBuffer).digest('hex');
    expect(actualHash).toBe(updated.sha256);
    expect(artifactBuffer.subarray(0, 5).toString('utf8')).toBe('%PDF-');
  });

  it('generates a COMPLETED report for a case-linked email, fetching the real case scoped to the organization', async () => {
    const c = await prisma.case.create({ data: { organizationId: orgA, title: 'Report Worker Linked Case' } });
    const linkedEmail = await prisma.email.create({
      data: {
        organizationId: orgA,
        caseId: c.id,
        sha256: crypto.randomBytes(32).toString('hex'),
        analysisStatus: 'COMPLETED',
        senderAddress: 'attacker@evil.example',
      },
    });
    await prisma.emailAddress.create({
      data: { emailId: linkedEmail.id, headerName: 'to', address: 'victim@example.com', raw: 'victim@example.com' },
    });

    const report = await prisma.forensicReport.create({
      data: { organizationId: orgA, emailId: linkedEmail.id, reportVersion: '1.0' },
    });
    await worker.generate(report.id, orgA);

    const updated = await prisma.forensicReport.findUniqueOrThrow({ where: { id: report.id } });
    expect(updated.status).toBe('COMPLETED');
    expect(updated.sha256).toMatch(/^[a-f0-9]{64}$/);

    await prisma.forensicReport.deleteMany({ where: { emailId: linkedEmail.id } });
    await prisma.emailAddress.deleteMany({ where: { emailId: linkedEmail.id } });
    await prisma.email.deleteMany({ where: { id: linkedEmail.id } });
    await prisma.case.deleteMany({ where: { id: c.id } });
  });

  it('refuses to generate a report for a report ID belonging to a different organization', async () => {
    const report = await prisma.forensicReport.create({
      data: { organizationId: orgA, emailId: emailAId, reportVersion: '2.0' },
    });

    await expect(worker.generate(report.id, orgB)).rejects.toThrow();

    const unchanged = await prisma.forensicReport.findUniqueOrThrow({ where: { id: report.id } });
    expect(unchanged.status).toBe('QUEUED');
    await prisma.forensicReport.delete({ where: { id: report.id } });
  });

  it('marks the report FAILED with a real error message when artifact storage fails, and rethrows', async () => {
    const report = await prisma.forensicReport.create({
      data: { organizationId: orgA, emailId: emailAId, reportVersion: '3.0' },
    });

    const brokenStore = {
      put: async () => { throw new Error('Simulated storage failure'); },
      get: store.get.bind(store),
      exists: store.exists.bind(store),
      delete: store.delete.bind(store),
    };
    const brokenWorker = new ReportGenerationWorker(prisma, brokenStore);

    await expect(brokenWorker.generate(report.id, orgA)).rejects.toThrow('Simulated storage failure');

    const failed = await prisma.forensicReport.findUniqueOrThrow({ where: { id: report.id } });
    expect(failed.status).toBe('FAILED');
    expect(failed.errorMessage).toBe('Simulated storage failure');
  });
});
