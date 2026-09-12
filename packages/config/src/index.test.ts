import { describe, it, expect } from 'vitest';
import { envSchema } from './index';

describe('Config Schema', () => {
  it('should validate correct environment variables', () => {
    const result = envSchema.safeParse({
      NODE_ENV: 'test',
      PORT: '4000',
      JWT_SECRET: 'super-secret-key-that-is-at-least-32-chars-long!',
      DATABASE_URL: 'postgres://user:pass@localhost:5432/db',
      REDIS_URL: 'redis://localhost:6379',
    });
    
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.PORT).toBe(4000);
      expect(result.data.NODE_ENV).toBe('test');
    }
  });

  it('should fail on invalid URL', () => {
    const result = envSchema.safeParse({
      JWT_SECRET: 'super-secret-key-that-is-at-least-32-chars-long!',
      DATABASE_URL: 'not-a-url',
    });
    
    expect(result.success).toBe(false);
  });
});
