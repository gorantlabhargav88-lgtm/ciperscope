import { logger } from '@ciperscope/logger';
import { CtiReevaluationCoordinator } from './CtiReevaluationCoordinator';

// Distinguishes a CTI-triggered re-evaluation job from the initial
// post-ingestion 'ml-classification' job on the same 'email-ml-classification'
// queue, so it gets its own idempotency record and never collides with, or is
// silently skipped by, the first evaluation's idempotency entry.
export const CTI_REEVALUATION_OPERATION = 'cti-reevaluation';

export interface CtiReevaluationQueue {
  add(name: string, data: unknown, opts: { jobId: string }): Promise<unknown>;
}

// A fixed BullMQ job ID per email guarantees at most one re-evaluation job is
// ever in flight for that email at a time, independent of the Redis counter.
export function ctiReevaluationBullJobId(emailId: string): string {
  return `ml-reeval-${emailId}`;
}

export function buildCtiReevaluationJobData(emailId: string, organizationId: string, upstreamJobId: string) {
  return {
    organizationId,
    resourceId: emailId,
    jobId: upstreamJobId,
    operation: CTI_REEVALUATION_OPERATION,
    emailId
  };
}

/**
 * Called once per IOC job's terminal outcome (completed, or failed with no
 * retries left). Enqueues exactly one CTI re-evaluation job for the email
 * once every IOC job fanned out for it has reached a terminal state —
 * regardless of whether each one individually succeeded or failed. Never
 * throws: a scheduling failure must not take down the CTI pipeline: the
 * email simply keeps whatever risk assessment it already has.
 *
 * This only ever enqueues onto the existing 'email-ml-classification' queue,
 * never back onto 'ioc-cti-enrichment' or 'email-cti-enrichment', so it
 * cannot create a CTI -> ML -> CTI loop.
 */
export async function scheduleCtiReevaluationIfComplete(
  emailId: string,
  organizationId: string,
  upstreamJobId: string,
  coordinator: CtiReevaluationCoordinator,
  reevaluationQueue: CtiReevaluationQueue
): Promise<boolean> {
  try {
    const isLastIoc = await coordinator.recordTerminalOutcome(emailId);
    if (!isLastIoc) return false;

    await reevaluationQueue.add(
      'ml-classification',
      buildCtiReevaluationJobData(emailId, organizationId, upstreamJobId),
      { jobId: ctiReevaluationBullJobId(emailId) }
    );
    logger.info({ emailId }, 'Scheduled CTI-triggered risk re-evaluation');
    return true;
  } catch (err) {
    logger.error({ err, emailId }, 'Failed to schedule CTI re-evaluation');
    return false;
  }
}

/**
 * True only once an IOC job has exhausted its retries — i.e. this is its
 * true terminal failure, not one of possibly several intermediate attempts
 * that BullMQ will still retry.
 */
export function isTerminalIocFailure(attemptsMade: number, maxAttempts: number): boolean {
  return attemptsMade >= maxAttempts;
}
