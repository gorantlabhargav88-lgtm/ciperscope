import { z } from 'zod';
import dotenv from 'dotenv';
import path from 'path';

// Note: Ensure the app requiring this package has a way to resolve the .env correctly.
// Since it's a monorepo, looking up up up might hit the root.
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

export const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().transform(Number).default('3000'),
  WORKER_PORT: z.string().transform(Number).default('3001'),
  CORS_ORIGIN: z.string().default('http://localhost:5173').transform((val) => val.split(',').map(s => s.trim())),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters long for secure HS256'),
  DATABASE_URL: z.string().url('DATABASE_URL must be a valid PostgreSQL connection string'),
  REDIS_URL: z.string().url('REDIS_URL must be a valid Redis connection string').default('redis://localhost:6379'),
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GOOGLE_OAUTH_REDIRECT_URI: z.string().optional(),
  GOOGLE_PUBSUB_TOPIC: z.string().optional(),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success && process.env.NODE_ENV !== 'test' && !process.env.VITEST) {
  console.error('❌ Invalid environment variables:');
  console.error(JSON.stringify(parsed.error.format(), null, 2));
  process.exit(1); // Fail fast in production
}

export const env = parsed.success ? parsed.data : (process.env as any);
