import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CircuitBreaker, CircuitBreakerState } from '../CircuitBreaker';

describe('CircuitBreaker', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('starts CLOSED and allows execution', () => {
    const cb = new CircuitBreaker('test');
    expect(cb.getState()).toBe(CircuitBreakerState.CLOSED);
    expect(cb.canExecute()).toBe(true);
  });

  it('opens after failure threshold is reached', () => {
    const cb = new CircuitBreaker('test', 5, 30000);
    for (let i = 0; i < 4; i++) {
      cb.recordFailure();
      expect(cb.getState()).toBe(CircuitBreakerState.CLOSED);
    }

    cb.recordFailure(); // 5th failure
    expect(cb.getState()).toBe(CircuitBreakerState.OPEN);
    expect(cb.canExecute()).toBe(false);
  });

  it('transitions to HALF_OPEN after reset timeout', () => {
    const cb = new CircuitBreaker('test', 5, 30000);
    for (let i = 0; i < 5; i++) {
      cb.recordFailure();
    }
    expect(cb.getState()).toBe(CircuitBreakerState.OPEN);

    // Move time forward past 30 seconds
    vi.advanceTimersByTime(30001);

    expect(cb.getState()).toBe(CircuitBreakerState.HALF_OPEN);
    expect(cb.canExecute()).toBe(true);
  });

  it('returns to CLOSED on success during HALF_OPEN', () => {
    const cb = new CircuitBreaker('test', 5, 30000);
    for (let i = 0; i < 5; i++) {
      cb.recordFailure();
    }
    vi.advanceTimersByTime(30001);

    expect(cb.getState()).toBe(CircuitBreakerState.HALF_OPEN);

    // Simulate successful request
    cb.recordSuccess();

    expect(cb.getState()).toBe(CircuitBreakerState.CLOSED);
    expect(cb.canExecute()).toBe(true);
  });

  it('returns to OPEN on failure during HALF_OPEN', () => {
    const cb = new CircuitBreaker('test', 5, 30000);
    for (let i = 0; i < 5; i++) {
      cb.recordFailure();
    }
    vi.advanceTimersByTime(30001);

    expect(cb.getState()).toBe(CircuitBreakerState.HALF_OPEN);

    // Simulate failed probe
    cb.recordFailure();

    expect(cb.getState()).toBe(CircuitBreakerState.OPEN);
    expect(cb.canExecute()).toBe(false);
  });

  it('allows ONLY ONE request during HALF_OPEN probe (concurrency test)', () => {
    const cb = new CircuitBreaker('test', 5, 30000);
    for (let i = 0; i < 5; i++) {
      cb.recordFailure();
    }

    // OPEN -> cooldown expires
    vi.advanceTimersByTime(30001);

    // First concurrent request becomes the only HALF_OPEN probe
    expect(cb.canExecute()).toBe(true);

    // Second concurrent request cannot execute the provider
    expect(cb.canExecute()).toBe(false);

    // Third concurrent request cannot execute the provider
    expect(cb.canExecute()).toBe(false);

    // successful probe -> CLOSED
    cb.recordSuccess();
    expect(cb.getState()).toBe(CircuitBreakerState.CLOSED);

    // Normal CLOSED behavior remains unchanged
    expect(cb.canExecute()).toBe(true);
    expect(cb.canExecute()).toBe(true);
  });

  it('resets failure count on success in CLOSED state', () => {
    const cb = new CircuitBreaker('test', 5, 30000);
    cb.recordFailure();
    cb.recordFailure(); // 2 failures

    cb.recordSuccess(); // Should reset to 0

    for (let i = 0; i < 4; i++) {
      cb.recordFailure(); // These 4 shouldn't trigger OPEN since it was reset
    }

    expect(cb.getState()).toBe(CircuitBreakerState.CLOSED);
  });
});
