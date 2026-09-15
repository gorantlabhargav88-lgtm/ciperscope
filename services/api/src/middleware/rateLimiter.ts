import { FastifyRequest, FastifyReply } from 'fastify';
import { createRedisConnection } from '@ciperscope/queue';
import { env } from '@ciperscope/config';
import { logger } from '@ciperscope/logger';

const redis = createRedisConnection(env.REDIS_URL || 'redis://127.0.0.1:6379');

export interface RateLimitOptions {
  key: string;
  max: number;
  windowSec: number;
  failOpen: boolean;
  errorMessage?: string;
}

export async function checkRateLimit(options: RateLimitOptions): Promise<{ allowed: boolean; retryAfter: number }> {
  try {
    const current = await redis.incr(options.key);
    if (current === 1) {
      await redis.expire(options.key, options.windowSec);
    }
    const ttl = await redis.ttl(options.key);
    
    return {
      allowed: current <= options.max,
      retryAfter: ttl > 0 ? ttl : options.windowSec,
    };
  } catch (err) {
    logger.error({ err, key: options.key }, 'Redis rate limiting failed');
    if (options.failOpen) {
      return { allowed: true, retryAfter: 0 };
    }
    throw new Error('Rate limiter unavailable');
  }
}

export const multiRateLimit = (limits: ((req: FastifyRequest) => RateLimitOptions | null)[]) => {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    for (const limitFn of limits) {
      const options = limitFn(request);
      if (!options) continue;

      try {
        const { allowed, retryAfter } = await checkRateLimit(options);
        if (!allowed) {
          reply.header('Retry-After', retryAfter);
          return reply.status(429).send({
            error: 'Too Many Requests',
            message: options.errorMessage || 'Rate limit exceeded'
          });
        }
      } catch (err) {
        return reply.status(503).send({
          error: 'Service Unavailable',
          message: 'Security controls temporarily unavailable'
        });
      }
    }
  };
};
