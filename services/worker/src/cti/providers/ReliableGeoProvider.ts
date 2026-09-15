import { IGeoProvider, GeoLocationResult } from './ICtiProvider';
import { CircuitBreaker, CircuitBreakerState } from './CircuitBreaker';
import { logger } from '@ciperscope/logger';
import IORedis from 'ioredis';
import { createHash } from 'crypto';

export class ReliableGeoProvider implements IGeoProvider {
  private underlying: IGeoProvider;
  private redis: IORedis;
  private circuitBreaker: CircuitBreaker;
  private readonly timeoutMs: number = 2000;
  private readonly ttlSuccessS: number = 86400; // 24 hours
  private readonly ttlUnknownS: number = 3600; // 1 hour

  constructor(underlying: IGeoProvider, redis: IORedis) {
    this.underlying = underlying;
    this.redis = redis;
    this.circuitBreaker = new CircuitBreaker(`cb_geo_${underlying.name}`);
  }

  public get name(): string {
    return this.underlying.name; // Preserve underlying provider name
  }

  private generateCacheKey(ipAddress: string): string {
    const hash = createHash('sha256').update(ipAddress).digest('hex');
    return `geo:cache:v1:${this.name}:${hash}`;
  }

  private validateGeoResult(result: unknown): GeoLocationResult | null {
    if (result === null) return null;
    if (typeof result !== 'object') {
      throw new Error('Malformed provider response: result is not an object');
    }
    const geoResult = result as Partial<GeoLocationResult>;

    if (!geoResult.providerName || typeof geoResult.providerName !== 'string' || geoResult.providerName.length > 255) {
      throw new Error('Malformed provider response: missing, invalid, or oversized providerName');
    }
    if (geoResult.country !== undefined && (typeof geoResult.country !== 'string' || geoResult.country.length > 255)) {
      throw new Error('Malformed provider response: invalid or oversized country');
    }
    if (geoResult.city !== undefined && (typeof geoResult.city !== 'string' || geoResult.city.length > 255)) {
      throw new Error('Malformed provider response: invalid or oversized city');
    }
    if (geoResult.asn !== undefined && (typeof geoResult.asn !== 'string' || geoResult.asn.length > 255)) {
      throw new Error('Malformed provider response: invalid or oversized asn');
    }
    if (geoResult.isp !== undefined && (typeof geoResult.isp !== 'string' || geoResult.isp.length > 255)) {
      throw new Error('Malformed provider response: invalid or oversized isp');
    }

    return geoResult as GeoLocationResult;
  }

  public async lookup(ipAddress: string): Promise<GeoLocationResult | null> {
    const cacheKey = this.generateCacheKey(ipAddress);

    try {
      // 1. Try Cache
      const cached = await this.redis.get(cacheKey);
      if (cached) {
        if (cached === 'null') return null;
        const parsed = JSON.parse(cached);
        return this.validateGeoResult(parsed);
      }
    } catch (err) {
      logger.error({ err, provider: this.name }, 'Redis cache retrieval or validation failed in ReliableGeoProvider');
      // Fall through on Redis failure or Cache Validation failure
    }

    // 2. Circuit Breaker Check
    if (!this.circuitBreaker.canExecute()) {
      logger.warn({ provider: this.name }, 'Circuit Breaker is OPEN. Falling back to null.');
      return null; // For GEO, UNKNOWN is represented as null
    }

    // 3. Execute with Timeout
    let timeoutHandle: NodeJS.Timeout | undefined;
    try {
      const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutHandle = setTimeout(() => reject(new Error('Provider Timeout')), this.timeoutMs);
      });

      const rawResult = await Promise.race([
        this.underlying.lookup(ipAddress),
        timeoutPromise
      ]);

      // 3.5 Validate Result (Defect 3 Fix)
      const result = this.validateGeoResult(rawResult);

      // Execution succeeded
      this.circuitBreaker.recordSuccess();

      // 4. Cache Result
      try {
        const ttl = result === null ? this.ttlUnknownS : this.ttlSuccessS;
        const cacheValue = result === null ? 'null' : JSON.stringify(result);
        await this.redis.set(cacheKey, cacheValue, 'EX', ttl);
      } catch (err) {
        logger.error({ err, provider: this.name }, 'Redis cache storage failed in ReliableGeoProvider');
      }

      return result;

    } catch (err) {
      // Execution failed (Timeout, Exception, Validation, etc.)
      this.circuitBreaker.recordFailure();

      if (this.circuitBreaker.getState() === CircuitBreakerState.OPEN) {
         logger.warn({ provider: this.name }, 'Circuit Breaker tripped to OPEN due to consecutive failures');
      }

      return null;
    } finally {
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }
    }
  }
}
