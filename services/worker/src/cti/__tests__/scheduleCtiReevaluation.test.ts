import { describe, it, expect, vi } from 'vitest';
import {
  scheduleCtiReevaluationIfComplete,
  isTerminalIocFailure,
  buildCtiReevaluationJobData,
  ctiReevaluationBullJobId,
  CTI_REEVALUATION_OPERATION,
  CtiReevaluationQueue
} from '../scheduleCtiReevaluation';
import { CtiReevaluationCoordinator } from '../CtiReevaluationCoordinator';

vi.mock('@ciperscope/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }
}));

describe('isTerminalIocFailure', () => {
  it('is false while attempts remain', () => {
    expect(isTerminalIocFailure(1, 3)).toBe(false);
    expect(isTerminalIocFailure(2, 3)).toBe(false);
  });

  it('is true once attempts are exhausted', () => {
    expect(isTerminalIocFailure(3, 3)).toBe(true);
    expect(isTerminalIocFailure(4, 3)).toBe(true);
  });
});

describe('buildCtiReevaluationJobData / ctiReevaluationBullJobId', () => {
  it('produces a job payload tagged with the CTI re-evaluation operation, not a CTI-enrichment operation', () => {
    const data = buildCtiReevaluationJobData('email-1', 'org-1', 'upstream-job-9');

    expect(data.operation).toBe(CTI_REEVALUATION_OPERATION);
    expect(data.operation).not.toMatch(/cti-enrichment/);
    expect(data).toEqual({
      organizationId: 'org-1',
      resourceId: 'email-1',
      jobId: 'upstream-job-9',
      operation: 'cti-reevaluation',
      emailId: 'email-1'
    });
  });

  it('derives a stable, per-email BullMQ job id so only one re-evaluation can be in flight per email', () => {
    expect(ctiReevaluationBullJobId('email-1')).toBe('ml-reeval-email-1');
    expect(ctiReevaluationBullJobId('email-1')).toBe(ctiReevaluationBullJobId('email-1'));
  });
});

describe('scheduleCtiReevaluationIfComplete', () => {
  const makeCoordinator = (isLast: boolean) =>
    ({ recordTerminalOutcome: vi.fn().mockResolvedValue(isLast) }) as unknown as CtiReevaluationCoordinator;

  it('does not enqueue anything while other IOC jobs for the email are still pending', async () => {
    const coordinator = makeCoordinator(false);
    const queue: CtiReevaluationQueue = { add: vi.fn().mockResolvedValue(undefined) };

    const triggered = await scheduleCtiReevaluationIfComplete('email-1', 'org-1', 'job-1', coordinator, queue);

    expect(triggered).toBe(false);
    expect(queue.add).not.toHaveBeenCalled();
  });

  it('enqueues exactly one re-evaluation job onto the existing email-ml-classification queue once the last IOC finishes', async () => {
    const coordinator = makeCoordinator(true);
    const queue: CtiReevaluationQueue = { add: vi.fn().mockResolvedValue(undefined) };

    const triggered = await scheduleCtiReevaluationIfComplete('email-1', 'org-1', 'job-1', coordinator, queue);

    expect(triggered).toBe(true);
    expect(queue.add).toHaveBeenCalledTimes(1);
    expect(queue.add).toHaveBeenCalledWith(
      'ml-classification',
      expect.objectContaining({ operation: CTI_REEVALUATION_OPERATION, emailId: 'email-1', organizationId: 'org-1' }),
      { jobId: 'ml-reeval-email-1' }
    );
  });

  it('never enqueues back onto a CTI-enrichment queue, so it cannot create a re-evaluation loop', async () => {
    const coordinator = makeCoordinator(true);
    const queue: CtiReevaluationQueue = { add: vi.fn().mockResolvedValue(undefined) };

    await scheduleCtiReevaluationIfComplete('email-1', 'org-1', 'job-1', coordinator, queue);

    const [queueName] = (queue.add as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(queueName).not.toMatch(/cti-enrichment/);
  });

  it('does not throw when scheduling fails, so a broken re-evaluation dispatch cannot take down the CTI pipeline', async () => {
    const coordinator = makeCoordinator(true);
    const queue: CtiReevaluationQueue = { add: vi.fn().mockRejectedValue(new Error('Redis down')) };

    await expect(
      scheduleCtiReevaluationIfComplete('email-1', 'org-1', 'job-1', coordinator, queue)
    ).resolves.toBe(false);
  });
});
