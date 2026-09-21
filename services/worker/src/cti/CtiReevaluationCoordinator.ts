import IORedis from 'ioredis';
import { logger } from '@ciperscope/logger';

const PENDING_KEY_PREFIX = 'cti-reeval-pending:';
// Generous relative to the ioc-cti-enrichment queue's retry window (3 attempts,
// exponential backoff), so a stuck/lost job can't hold this counter open forever.
const PENDING_TTL_SECONDS = 2 * 60 * 60;

/**
 * Coordinates re-evaluating an email's risk score once all of the IOC
 * enrichment jobs fanned out for it have reached a terminal state (completed,
 * or failed with no retries left).
 *
 * An email can produce many IOC jobs; FusionEngine must only be re-run once
 * per email, not once per IOC. This uses a single Redis counter per email,
 * decremented atomically, so exactly one caller observes it reach zero.
 */
export class CtiReevaluationCoordinator {
  constructor(private readonly redis: IORedis) {}

  /**
   * Records how many IOC jobs were fanned out for this email. Must be called
   * before any of those jobs can report a terminal outcome. A count of 0
   * means nothing was enqueued, so there is nothing to wait for.
   */
  public async initPending(emailId: string, count: number): Promise<void> {
    if (count <= 0) return;
    await this.redis.set(PENDING_KEY_PREFIX + emailId, count, 'EX', PENDING_TTL_SECONDS);
  }

  /**
   * Call exactly once per IOC job's terminal outcome for this email. Returns
   * true only for the single call that brings the counter to zero — that
   * caller, and only that caller, should trigger the re-evaluation.
   */
  public async recordTerminalOutcome(emailId: string): Promise<boolean> {
    const key = PENDING_KEY_PREFIX + emailId;
    const remaining = await this.redis.decr(key);

    if (remaining === 0) {
      await this.redis.del(key);
      return true;
    }

    if (remaining < 0) {
      // Counter was never initialized, already expired, or already consumed.
      // Do not trigger — a missing baseline means we cannot safely tell
      // whether this is really the last job.
      logger.warn({ emailId, remaining }, 'CTI re-evaluation counter went negative; not triggering');
    }

    return false;
  }
}
