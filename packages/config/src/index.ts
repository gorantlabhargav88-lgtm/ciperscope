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
  // Encrypts Gmail OAuth access/refresh tokens at rest (AES-256-GCM — see
  // ./tokenCrypto.ts). Required whenever Gmail integration is used; kept
  // optional at the schema level (like the other GOOGLE_* vars) so
  // environments that don't use Gmail aren't forced to set it, but
  // services/api and services/worker's Gmail code paths fail fast if this
  // is missing when actually needed.
  GMAIL_TOKEN_ENCRYPTION_KEY: z.string().min(32, 'GMAIL_TOKEN_ENCRYPTION_KEY must be at least 32 characters long').optional(),
  // Raw-email object storage. S3_* select the S3-backed store; when unset,
  // both services/api and services/worker fall back to LocalRawEmailStore.
  // RAW_EMAIL_STORAGE_PATH pins the local store to one shared absolute
  // directory — without it, each process defaulted to `process.cwd()`,
  // which diverges whenever api and worker are started from different
  // working directories, causing every locally-stored raw email the API
  // wrote to be invisible to the worker's parsing stage.
  S3_BUCKET: z.string().optional(),
  S3_REGION: z.string().optional(),
  S3_ENDPOINT: z.string().optional(),
  RAW_EMAIL_STORAGE_PATH: z.string().optional(),
  // Phase H: MaxMind GeoIP2 City web service (HTTP + Basic Auth, not the
  // downloadable .mmdb database). Both optional — when either is unset,
  // services/worker/src/cti/CtiConfig.ts falls back to NullGeoProvider
  // (geolocation becomes UNAVAILABLE, never fabricated).
  MAXMIND_ACCOUNT_ID: z.string().optional(),
  MAXMIND_LICENSE_KEY: z.string().optional(),
  // Phase L: RDAP domain intelligence. RDAP itself needs no credentials
  // (public protocol), but this lets ops disable outbound RDAP lookups
  // entirely; when unset/true, RDAP is used. See DomainIntelConfig.ts.
  RDAP_ENABLED: z.enum(['true', 'false']).optional(),
  // ML Service configuration (DistilBERT inference service)
  ML_SERVICE_TOKEN: z.string().optional(),
  ML_SERVICE_URL: z.string().optional(),
  // Organization-invitation email delivery (packages/providers/src/email).
  // All optional — when SMTP_HOST/SMTP_PORT/SMTP_FROM are unset, invitation
  // creation falls back to NullEmailProvider (no email sent, never
  // fabricated) and, outside production only, returns a dev invite URL
  // directly in the API response instead.
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().int().optional(),
  SMTP_USER: z.string().optional(),
  SMTP_PASSWORD: z.string().optional(),
  SMTP_FROM: z.string().optional(),
  SMTP_SECURE: z.enum(['true', 'false']).optional(),
  // Blockchain evidence notarization & anchoring configuration
  BLOCKCHAIN_ENABLED: z.enum(['true', 'false']).default('false').optional(),
  BLOCKCHAIN_NETWORK: z.string().default('sepolia').optional(),
  BLOCKCHAIN_RPC_URL: z.string().optional(),
  BLOCKCHAIN_CHAIN_ID: z.coerce.number().int().optional(),
  BLOCKCHAIN_PRIVATE_KEY: z.string().optional(),
  BLOCKCHAIN_CONTRACT_ADDRESS: z.string().optional(),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success && process.env.NODE_ENV !== 'test' && !process.env.VITEST) {
  console.error('❌ Invalid environment variables:');
  console.error(JSON.stringify(parsed.error.format(), null, 2));
  process.exit(1); // Fail fast in production
}

export const env = parsed.success ? parsed.data : (process.env as any);

export * from './tokenCrypto';

/**
 * Shared default directory for LocalRawEmailStore, resolved relative to this
 * package's build output the same way the .env path above is (dist -> repo
 * root is 3 levels up). Used by both services/api and services/worker so a
 * raw email written by one process is always found by the other when
 * RAW_EMAIL_STORAGE_PATH is not explicitly set and S3 is not configured.
 */
export const defaultRawEmailStoragePath =
  env.RAW_EMAIL_STORAGE_PATH || path.resolve(__dirname, '../../../.data/emails');

/** Throws a clear, actionable error at the exact point Gmail token encryption is needed, rather than failing app-wide startup for an optional feature. */
export function requireGmailTokenEncryptionKey(): string {
  if (!env.GMAIL_TOKEN_ENCRYPTION_KEY) {
    throw new Error(
      'GMAIL_TOKEN_ENCRYPTION_KEY is not configured. Set it to a random 32+ character secret before using Gmail integration (see .env.example).'
    );
  }
  return env.GMAIL_TOKEN_ENCRYPTION_KEY;
}

/** Returns true if blockchain anchoring is enabled in configuration. */
export function isBlockchainEnabled(): boolean {
  return env.BLOCKCHAIN_ENABLED === 'true';
}

/** Returns true if blockchain anchoring has full configuration (enabled, RPC URL, contract, private key). */
export function isBlockchainConfigured(): boolean {
  return (
    env.BLOCKCHAIN_ENABLED === 'true' &&
    !!env.BLOCKCHAIN_RPC_URL &&
    !!env.BLOCKCHAIN_CONTRACT_ADDRESS &&
    !!env.BLOCKCHAIN_PRIVATE_KEY
  );
}
