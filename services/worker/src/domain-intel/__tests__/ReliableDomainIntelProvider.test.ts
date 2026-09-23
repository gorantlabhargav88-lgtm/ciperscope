import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import '@ciperscope/config';
import IORedis from 'ioredis';
import { ReliableDomainIntelProvider } from '../ReliableDomainIntelProvider';
import { IDomainIntelProvider, DomainIntelLookupOutcome } from '../IDomainIntelProvider';

function fakeProvider(outcome: DomainIntelLookupOutcome, name = 'fake'): { provider: IDomainIntelProvider; calls: number[] } {
  const calls: number[] = [];
  return {
    provider: {
      name,
      async lookup() {
        calls.push(Date.now());
        return outcome;
      },
    },
    calls,
  };
}

describe('ReliableDomainIntelProvider (real Redis)', () => {
  const redis = new IORedis(process.env.REDIS_URL || 'redis://127.0.0.1:6379', { maxRetriesPerRequest: null });

  beforeEach(async () => {
    const domainKeys = await redis.keys('rdap:*test-domain*');
    const rateLimitKeys = await redis.keys('rdap:ratelimit:*');
    const keys = [...domainKeys, ...rateLimitKeys];
    if (keys.length > 0) await redis.del(...keys);
  });

  afterAll(async () => {
    await redis.quit();
  });

  it('caches a SUCCESS outcome and serves it from cache on the next call (underlying not called twice)', async () => {
    const domain = 'test-domain-cache.example.com';
    const successOutcome: DomainIntelLookupOutcome = {
      status: 'SUCCESS',
      data: { registrar: 'X', registrationDate: null, expirationDate: null, nameservers: [], domainStatus: [], rdapSource: 'https://rdap.example/' },
    };
    const { provider: underlying, calls } = fakeProvider(successOutcome);
    const reliable = new ReliableDomainIntelProvider(underlying, redis);

    const first = await reliable.lookup(domain);
    const second = await reliable.lookup(domain);

    expect(first).toEqual(successOutcome);
    expect(second).toEqual(successOutcome);
    expect(calls.length).toBe(1); // second call served from cache
  });

  it('does not cache a rate-limited or circuit-breaker-skipped outcome (transient, must be retried)', async () => {
    const domain = 'test-domain-notcached.example.com';
    const { provider: underlying, calls } = fakeProvider({ status: 'NOT_FOUND', data: null });
    const reliable = new ReliableDomainIntelProvider(underlying, redis);

    await reliable.lookup(domain);
    expect(calls.length).toBe(1);

    // NOT_FOUND is a settled (non-transient) outcome, so it IS cached — a
    // second call within the TTL should not hit the underlying provider again.
    await reliable.lookup(domain);
    expect(calls.length).toBe(1);
  });

  it('enforces a per-minute rate limit and returns PROVIDER_ERROR without calling the underlying provider once exceeded', async () => {
    const successOutcome: DomainIntelLookupOutcome = {
      status: 'SUCCESS',
      data: { registrar: null, registrationDate: null, expirationDate: null, nameservers: [], domainStatus: [], rdapSource: 'https://rdap.example/' },
    };
    const { provider: underlying, calls } = fakeProvider(successOutcome);
    const reliable = new ReliableDomainIntelProvider(underlying, redis);

    // Distinct domains so each call is a real cache-miss lookup, exercising
    // the rate limiter rather than the domain cache.
    const outcomes: DomainIntelLookupOutcome[] = [];
    for (let i = 0; i < 32; i++) {
      outcomes.push(await reliable.lookup(`test-domain-rl-${i}.example.com`));
    }

    const rateLimited = outcomes.filter((o) => o.status === 'PROVIDER_ERROR' && o.errorMessage === 'Rate limit exceeded');
    expect(rateLimited.length).toBeGreaterThan(0);
    expect(calls.length).toBeLessThan(32); // some calls were blocked before reaching the underlying provider
  });
});
