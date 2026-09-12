import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    env: {
      DATABASE_URL: process.env.DATABASE_URL || 'postgresql://ciperscope_user:ciperscope_password@127.0.0.1:5432/ciperscope_db?schema=public',
      REDIS_URL: process.env.REDIS_URL || 'redis://127.0.0.1:6379',
    }
  },
});
