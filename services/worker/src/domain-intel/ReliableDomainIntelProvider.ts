import IORedis from 'ioredis';
import { logger } from '@ciperscope/logger';
import { CircuitBreaker, CircuitBreakerState } from '../cti/providers/CircuitBreaker';
import { IDomainIntelProvider, DomainIntelLookupOutcome } from './IDomainIntelProvider';

const TTL_SUCCESS_S = 86400; // 24h — registration data changes rarely
const TTL_NEGATIVE_S = 3600; // 1h — NOT_FOUND/errors, retried sooner
const RATE_LIMIT_MAX_PER_MINUTE = 30;

/**
 * Wraps an IDomainIntelProvider with the same reliability shape already
 * established by ReliableGeoProvider: Redis cache, circuit breaker,
 * timeout — plus an explicit rate limiter (RDAP has no per-request API key
 * to naturally bound call volume the way CTI/GeoIP providers do).
 */
export class ReliableDomainIntelProvider implements IDomainIntelProvider {
  private readonly underlying: IDomainIntelProvider;
  private readonly redis: IORedis;
  private readonly circuitBreaker: CircuitBreaker;
  private readonly timeoutMs = 6000;

  constructor(underlying: IDomainIntelProvider, redis: IORedis) {
    this.underlying = underlying;
    this.redis = redis;
    this.circuitBreaker = new CircuitBreaker(`cb_domain_intel_${underlying.name}`);
  }

  public get name(): string {
    return this.underlying.name;
  }

  private cacheKey(domain: string): string {
    return `rdap:cache:v1:${domain}`;
  }

  private async isRateLimited(): Promise<boolean> {
    const windowKey = `rdap:ratelimit:${Math.floor(Date.now() / 60000)}`;
    try {
      const count = await this.redis.incr(windowKey);
      if (count === 1) await this.redis.expire(windowKey, 60);
      return count > RATE_LIMIT_MAX_PER_MINUTE;
    } catch (err) {
      logger.warn({ err }, 'RDAP rate-limit check failed; failing open');
      return false;
    }
  }

  public async lookup(registrableDomain: string): Promise<DomainIntelLookupOutcome> {
    const cacheKey = this.cacheKey(registrableDomain);

    try {
      const cached = await this.redis.get(cacheKey);
      if (cached) return JSON.parse(cached) as DomainIntelLookupOutcome;
    } catch (err) {
      logger.warn({ err, provider: this.name }, 'RDAP cache retrieval failed');
    }

    if (!this.circuitBreaker.canExecute()) {
      logger.warn({ provider: this.name }, 'RDAP circuit breaker is OPEN');
      return { status: 'PROVIDER_ERROR', data: null, errorMessage: 'Circuit breaker open' };
    }

    if (await this.isRateLimited()) {
      logger.warn({ provider: this.name }, 'RDAP rate limit exceeded for this window');
      return { status: 'PROVIDER_ERROR', data: null, errorMessage: 'Rate limit exceeded' };
    }

    let timeoutHandle: NodeJS.Timeout | undefined;
    try {
      const timeoutPromise = new Promise<DomainIntelLookupOutcome>((_, reject) => {
        timeoutHandle = setTimeout(() => reject(new Error('Provider Timeout')), this.timeoutMs);
      });
      const outcome = await Promise.race([this.underlying.lookup(registrableDomain), timeoutPromise]);

      if (outcome.status === 'PROVIDER_ERROR' || outcome.status === 'PROVIDER_TIMEOUT') {
        this.circuitBreaker.recordFailure();
      } else {
        this.circuitBreaker.recordSuccess();
      }

      // Only cache genuinely-settled outcomes — never cache a rate-limit or
      // circuit-breaker skip (those are transient, not facts about the domain).
      try {
        const ttl = outcome.status === 'SUCCESS' ? TTL_SUCCESS_S : TTL_NEGATIVE_S;
        await this.redis.set(cacheKey, JSON.stringify(outcome), 'EX', ttl);
      } catch (err) {
        logger.warn({ err, provider: this.name }, 'RDAP cache storage failed');
      }

      return outcome;
    } catch (err) {
      this.circuitBreaker.recordFailure();
      if (this.circuitBreaker.getState() === CircuitBreakerState.OPEN) {
        logger.warn({ provider: this.name }, 'RDAP circuit breaker tripped to OPEN');
      }
      return { status: 'PROVIDER_TIMEOUT', data: null, errorMessage: err instanceof Error ? err.message : 'Unknown error' };
    } finally {
      if (timeoutHandle) clearTimeout(timeoutHandle);
    }
  }
}
