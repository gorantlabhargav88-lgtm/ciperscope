import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CtiReevaluationCoordinator } from '../CtiReevaluationCoordinator';
import IORedis from 'ioredis';

// Mock logger to avoid noisy test output
vi.mock('@ciperscope/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }
}));

describe('CtiReevaluationCoordinator', () => {
  let mockRedis: { set: ReturnType<typeof vi.fn>; decr: ReturnType<typeof vi.fn>; del: ReturnType<typeof vi.fn> };
  let coordinator: CtiReevaluationCoordinator;

  beforeEach(() => {
    mockRedis = {
      set: vi.fn().mockResolvedValue('OK'),
      decr: vi.fn(),
      del: vi.fn().mockResolvedValue(1)
    };
    coordinator = new CtiReevaluationCoordinator(mockRedis as unknown as IORedis);
  });

  describe('initPending', () => {
    it('sets a counter with an expiry when there are indicators to wait on', async () => {
      await coordinator.initPending('email-1', 5);

      expect(mockRedis.set).toHaveBeenCalledWith('cti-reeval-pending:email-1', 5, 'EX', expect.any(Number));
    });

    it('does not create a counter when there is nothing to wait on', async () => {
      await coordinator.initPending('email-1', 0);

      expect(mockRedis.set).not.toHaveBeenCalled();
    });
  });

  describe('recordTerminalOutcome', () => {
    it('returns false while jobs are still pending', async () => {
      mockRedis.decr.mockResolvedValue(2);

      const isLast = await coordinator.recordTerminalOutcome('email-1');

      expect(isLast).toBe(false);
      expect(mockRedis.del).not.toHaveBeenCalled();
    });

    it('returns true exactly when the counter reaches zero, and cleans up the key', async () => {
      mockRedis.decr.mockResolvedValue(0);

      const isLast = await coordinator.recordTerminalOutcome('email-1');

      expect(isLast).toBe(true);
      expect(mockRedis.del).toHaveBeenCalledWith('cti-reeval-pending:email-1');
    });

    it('does not trigger again when the counter is already consumed or missing', async () => {
      mockRedis.decr.mockResolvedValue(-1);

      const isLast = await coordinator.recordTerminalOutcome('email-1');

      expect(isLast).toBe(false);
      expect(mockRedis.del).not.toHaveBeenCalled();
    });

    it('lets exactly one caller observe zero when multiple IOC jobs finish concurrently for the same email', async () => {
      // A minimal in-memory stand-in for Redis's real atomicity guarantee on DECR:
      // each call synchronously computes and returns a distinct, monotonically
      // decreasing value, exactly like a single-threaded Redis server would.
      let counter = 5;
      mockRedis.decr.mockImplementation(async () => --counter);

      const results = await Promise.all(
        Array.from({ length: 5 }, () => coordinator.recordTerminalOutcome('email-1'))
      );

      expect(results.filter(Boolean)).toHaveLength(1);
    });
  });
});
