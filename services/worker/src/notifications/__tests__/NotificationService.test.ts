import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WebhookNotificationService } from '../NotificationService';

vi.mock('@ciperscope/logger', () => ({ logger: { info: vi.fn(), error: vi.fn(), warn: vi.fn() } }));

describe('WebhookNotificationService.notifyThreatAnalysisCompleted', () => {
  let prismaMock: any;
  let addMock: ReturnType<typeof vi.fn>;
  let queueManagerMock: any;

  beforeEach(() => {
    addMock = vi.fn().mockResolvedValue({ id: 'job-1' });
    prismaMock = { webhook: { findMany: vi.fn() } };
    queueManagerMock = { getQueue: vi.fn().mockReturnValue({ add: addMock }) };
  });

  it('enqueues one job per enabled webhook subscribed to THREAT_ANALYSIS_COMPLETED', async () => {
    prismaMock.webhook.findMany.mockResolvedValue([
      { id: 'wh-1', organizationId: 'org-1', enabled: true, events: ['THREAT_ANALYSIS_COMPLETED'] },
      { id: 'wh-2', organizationId: 'org-1', enabled: true, events: ['THREAT_ANALYSIS_COMPLETED'] },
    ]);

    const service = new WebhookNotificationService(prismaMock, queueManagerMock);
    await service.notifyThreatAnalysisCompleted({
      emailId: 'email-1', organizationId: 'org-1', threatScore: 55, priority: 'HIGH', threatCategory: 'PHISHING', analysisStatus: 'COMPLETED',
    });

    expect(addMock).toHaveBeenCalledTimes(2);
    expect(prismaMock.webhook.findMany).toHaveBeenCalledWith({ where: { organizationId: 'org-1', enabled: true } });
  });

  it('skips a webhook not subscribed to THREAT_ANALYSIS_COMPLETED', async () => {
    prismaMock.webhook.findMany.mockResolvedValue([
      { id: 'wh-1', organizationId: 'org-1', enabled: true, events: ['SOME_OTHER_EVENT'] },
    ]);

    const service = new WebhookNotificationService(prismaMock, queueManagerMock);
    await service.notifyThreatAnalysisCompleted({
      emailId: 'email-1', organizationId: 'org-1', threatScore: 10, priority: 'LOW', threatCategory: null, analysisStatus: 'COMPLETED',
    });

    expect(addMock).not.toHaveBeenCalled();
  });

  it('does not enqueue anything when there are no webhooks for the org (findMany already filters by org)', async () => {
    prismaMock.webhook.findMany.mockResolvedValue([]);
    const service = new WebhookNotificationService(prismaMock, queueManagerMock);
    await service.notifyThreatAnalysisCompleted({
      emailId: 'email-1', organizationId: 'org-2', threatScore: 0, priority: 'LOW', threatCategory: null, analysisStatus: 'COMPLETED',
    });
    expect(addMock).not.toHaveBeenCalled();
  });

  it('the enqueued payload contains only the minimal documented fields — never OAuth tokens, secrets, or raw email content', async () => {
    prismaMock.webhook.findMany.mockResolvedValue([
      { id: 'wh-1', organizationId: 'org-1', enabled: true, events: ['THREAT_ANALYSIS_COMPLETED'] },
    ]);

    const service = new WebhookNotificationService(prismaMock, queueManagerMock);
    await service.notifyThreatAnalysisCompleted({
      emailId: 'email-1', organizationId: 'org-1', threatScore: 72, priority: 'HIGH', threatCategory: 'PHISHING', analysisStatus: 'COMPLETED',
    });

    const [, jobPayload] = addMock.mock.calls[0];
    const payload = jobPayload.payload;

    expect(Object.keys(payload).sort()).toEqual(
      ['analysisStatus', 'emailId', 'eventId', 'eventType', 'organizationId', 'priority', 'threatCategory', 'threatScore', 'timestamp'].sort()
    );
    // Explicit negative assertions for the exact things the security
    // requirements forbid sending.
    const serialized = JSON.stringify(payload).toLowerCase();
    expect(serialized).not.toMatch(/accesstoken|refreshtoken|password|apikey|authorization|rawemail|subject|body/);
  });

  it('two organizations with independent webhooks each only get their own event delivered', async () => {
    prismaMock.webhook.findMany.mockImplementation(({ where }: any) => {
      if (where.organizationId === 'org-A') {
        return Promise.resolve([{ id: 'wh-A', organizationId: 'org-A', enabled: true, events: ['THREAT_ANALYSIS_COMPLETED'] }]);
      }
      return Promise.resolve([{ id: 'wh-B', organizationId: 'org-B', enabled: true, events: ['THREAT_ANALYSIS_COMPLETED'] }]);
    });

    const service = new WebhookNotificationService(prismaMock, queueManagerMock);
    await service.notifyThreatAnalysisCompleted({
      emailId: 'email-A', organizationId: 'org-A', threatScore: 10, priority: 'LOW', threatCategory: null, analysisStatus: 'COMPLETED',
    });

    expect(addMock).toHaveBeenCalledTimes(1);
    const [, jobPayloadA] = addMock.mock.calls[0];
    expect(jobPayloadA.webhookId).toBe('wh-A');
    expect(jobPayloadA.organizationId).toBe('org-A');
  });

  it('uses a deterministic jobId (eventId:webhookId) so BullMQ itself dedupes a re-enqueue of the same event', async () => {
    prismaMock.webhook.findMany.mockResolvedValue([
      { id: 'wh-1', organizationId: 'org-1', enabled: true, events: ['THREAT_ANALYSIS_COMPLETED'] },
    ]);
    const service = new WebhookNotificationService(prismaMock, queueManagerMock);
    await service.notifyThreatAnalysisCompleted({
      emailId: 'email-1', organizationId: 'org-1', threatScore: 5, priority: 'LOW', threatCategory: null, analysisStatus: 'COMPLETED',
    });

    const [, jobPayload, opts] = addMock.mock.calls[0];
    expect(opts.jobId).toBe(`${jobPayload.eventId}_wh-1`);
    expect(opts.jobId).not.toContain(':');
  });
});
