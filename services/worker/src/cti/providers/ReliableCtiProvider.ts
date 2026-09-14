import { ICtiProvider, CtiResult } from './ICtiProvider';
import { NormalizedIoc } from '../IocNormalizer';
import { CircuitBreaker, CircuitBreakerState } from './CircuitBreaker';
import { ThreatVerdict } from '@ciperscope/database';
import { logger } from '@ciperscope/logger';
import IORedis from 'ioredis';
import { createHash } from 'crypto';

export class ReliableCtiProvider implements ICtiProvider {
  private underlying: ICtiProvider;
  private redis: IORedis;
  private circuitBreaker: CircuitBreaker;
  private readonly timeoutMs: number = 2000;
  private readonly ttlSuccessS: number = 86400; // 24 hours
  private readonly ttlUnknownS: number = 3600; // 1 hour

  constructor(underlying: ICtiProvider, redis: IORedis) {
    this.underlying = underlying;
    this.redis = redis;
    this.circuitBreaker = new CircuitBreaker(`cb_cti_${underlying.name}`);
  }

  public get name(): string {
    return this.underlying.name; // Preserve underlying provider name
  }

  private generateCacheKey(ioc: NormalizedIoc): string {
    const hash = createHash('sha256').update(ioc.value).digest('hex');
    return `cti:cache:v1:${this.name}:${ioc.type}:${hash}`;
  }

  private validateCtiResult(result: unknown): CtiResult {
    if (!result || typeof result !== 'object') {
      throw new Error('Malformed provider response: result is not an object');
    }
    const ctiResult = result as Partial<CtiResult>;

    if (!ctiResult.status || !Object.values(ThreatVerdict).includes(ctiResult.status as ThreatVerdict)) {
      throw new Error(`Malformed provider response: invalid status ${ctiResult.status}`);
    }
    if (!ctiResult.providerName || typeof ctiResult.providerName !== 'string') {
      throw new Error('Malformed provider response: missing or invalid providerName');
    }
    if (ctiResult.confidence !== undefined) {
      if (typeof ctiResult.confidence !== 'number' || isNaN(ctiResult.confidence) || ctiResult.confidence < 0 || ctiResult.confidence > 100) {
        throw new Error(`Malformed provider response: invalid confidence ${ctiResult.confidence}`);
      }
    }
    if (ctiResult.metadata !== undefined) {
      if (typeof ctiResult.metadata !== 'object' || ctiResult.metadata === null || Array.isArray(ctiResult.metadata)) {
        throw new Error('Malformed provider response: invalid metadata');
      }
    }

    return ctiResult as CtiResult;
  }

  public async lookup(ioc: NormalizedIoc): Promise<CtiResult> {
    const cacheKey = this.generateCacheKey(ioc);

    try {
      // 1. Try Cache
      const cached = await this.redis.get(cacheKey);
      if (cached) {
        const parsed = JSON.parse(cached);
        return this.validateCtiResult(parsed);
      }
    } catch (err) {
      logger.error({ err, provider: this.name }, 'Redis cache retrieval or validation failed in ReliableCtiProvider');
      // Fall through on Redis failure or Cache Validation failure
    }

    // 2. Circuit Breaker Check
    if (!this.circuitBreaker.canExecute()) {
      logger.warn({ provider: this.name }, 'Circuit Breaker is OPEN. Falling back to UNKNOWN.');
      return this.fallbackUnknown('Circuit Breaker OPEN');
    }

    // 3. Execute with Timeout
    let timeoutHandle: NodeJS.Timeout | undefined;
    try {
      const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutHandle = setTimeout(() => reject(new Error('Provider Timeout')), this.timeoutMs);
      });

      const rawResult = await Promise.race([
        this.underlying.lookup(ioc),
        timeoutPromise
      ]);

      // 3.5 Validate Result (Defect 3 Fix)
      const result = this.validateCtiResult(rawResult);

      // Execution succeeded
      this.circuitBreaker.recordSuccess();

      // 4. Cache Result
      try {
        const ttl = result.status === ThreatVerdict.UNKNOWN ? this.ttlUnknownS : this.ttlSuccessS;
        await this.redis.set(cacheKey, JSON.stringify(result), 'EX', ttl);
      } catch (err) {
        logger.error({ err, provider: this.name }, 'Redis cache storage failed in ReliableCtiProvider');
      }

      return result;

    } catch (err) {
      // Execution failed (Timeout, Exception, Validation, etc.)
      this.circuitBreaker.recordFailure();

      const isTimeout = err instanceof Error && err.message === 'Provider Timeout';
      if (this.circuitBreaker.getState() === CircuitBreakerState.OPEN) {
         logger.warn({ provider: this.name }, 'Circuit Breaker tripped to OPEN due to consecutive failures');
      }

      const fallbackReason = isTimeout ? 'Provider Timeout' : (err instanceof Error ? err.message : 'Provider Error');
      return this.fallbackUnknown(fallbackReason);
    } finally {
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }
    }
  }

  private fallbackUnknown(reason: string): CtiResult {
    return {
      status: ThreatVerdict.UNKNOWN,
      providerName: this.name,
      metadata: { reliableFallbackReason: reason }
    };
  }
}
