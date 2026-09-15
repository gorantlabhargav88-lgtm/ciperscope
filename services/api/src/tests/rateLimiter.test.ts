import { describe, it, expect, vi, beforeEach } from 'vitest';
import { FastifyRequest, FastifyReply } from 'fastify';

// Hoist mock setup
vi.mock('@ciperscope/queue', () => {
  const store = new Map<string, number>();
  const ttlStore = new Map<string, number>();
  const mockObj = {
    incr: async (key: string) => {
      const val = (store.get(key) || 0) + 1;
      store.set(key, val);
      if (val === 1) ttlStore.set(key, Date.now());
      return val;
    },
    expire: async (key: string, sec: number) => {
      ttlStore.set(key, Date.now() + sec * 1000);
    },
    ttl: async (key: string) => {
      const exp = ttlStore.get(key) || 0;
      const remain = exp - Date.now();
      return remain > 0 ? Math.ceil(remain / 1000) : 0;
    },
    _clear: () => {
      store.clear();
      ttlStore.clear();
    },
    _fail: false,
    _setFail: (fail: boolean) => {}
  };
  return {
    createRedisConnection: () => mockObj,
    QueueManager: class {},
    IdempotencyManager: class {}
  };
});

import { checkRateLimit, multiRateLimit } from '../../src/middleware/rateLimiter';
import { createRedisConnection } from '@ciperscope/queue';

const redis = createRedisConnection('');

describe('Rate Limiter', () => {
  beforeEach(() => {
    (redis as any)._clear();
    (redis as any)._fail = false;
  });

  it('should allow requests under the limit', async () => {
    const res1 = await checkRateLimit({ key: 'test1', max: 2, windowSec: 60, failOpen: false });
    expect(res1.allowed).toBe(true);

    const res2 = await checkRateLimit({ key: 'test1', max: 2, windowSec: 60, failOpen: false });
    expect(res2.allowed).toBe(true);
  });

  it('should block requests over the limit and return 429 via middleware', async () => {
    let sentStatus = 200;
    const mockReply = {
      status: (code: number) => { sentStatus = code; return mockReply; },
      send: (body: any) => body,
      header: vi.fn(),
    } as unknown as FastifyReply;
    const mockReq = { ip: '1.2.3.4' } as FastifyRequest;

    const middleware = multiRateLimit([
      (req) => ({ key: `rl:test:${req.ip}`, max: 1, windowSec: 60, failOpen: false })
    ]);

    // First request should pass
    await middleware(mockReq, mockReply);
    expect(sentStatus).toBe(200);

    // Second request should fail 429
    await middleware(mockReq, mockReply);
    expect(sentStatus).toBe(429);
  });

  it('should fail closed for auth when redis is down', async () => {
    const origIncr = redis.incr;
    redis.incr = async () => { throw new Error('Redis down'); };

    const res = await checkRateLimit({ key: 'auth', max: 1, windowSec: 60, failOpen: false }).catch(e => e);
    expect(res).toBeInstanceOf(Error);

    redis.incr = origIncr;
  });

  it('should fail open for ingest when redis is down', async () => {
    const origIncr = redis.incr;
    redis.incr = async () => { throw new Error('Redis down'); };

    const res = await checkRateLimit({ key: 'ingest', max: 1, windowSec: 60, failOpen: true });
    expect(res.allowed).toBe(true);

    redis.incr = origIncr;
  });
});
