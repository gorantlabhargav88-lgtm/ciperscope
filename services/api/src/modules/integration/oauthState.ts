import { FastifyInstance } from 'fastify';
import { createRedisConnection } from '@ciperscope/queue';
import { env } from '@ciperscope/config';
import crypto from 'crypto';

/**
 * Secure OAuth `state` handling for the Gmail connect flow.
 *
 * Previously `state` was an unsigned base64-encoded JSON blob
 * (`Buffer.from(JSON.stringify({organizationId})).toString('base64')`) —
 * trivially forgeable/tamperable, with no expiry and no replay protection.
 *
 * This replaces it by integrating with the application's EXISTING session
 * mechanism (`@fastify/jwt`, already registered on the server and signed
 * with JWT_SECRET) rather than inventing a second signing scheme: the
 * state is a genuine short-lived JWT whose signature only our server could
 * have produced, carrying the initiating user/org as claims. A Redis-backed
 * single-use claim (atomic SET NX) makes it replay-resistant on top of
 * that, using the same Redis connection pattern already established in
 * services/api/src/middleware/rateLimiter.ts.
 */

const redis = createRedisConnection(env.REDIS_URL || 'redis://127.0.0.1:6379');

const STATE_TTL_SECONDS = 600; // 10 minutes — long enough for a real Google consent flow, short enough to bound replay exposure
const STATE_PURPOSE = 'gmail_oauth_state';

export class OAuthStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OAuthStateError';
  }
}

interface GmailOAuthStateClaims {
  sub: string;
  orgId: string;
  nonce: string;
  purpose: typeof STATE_PURPOSE;
}

export function issueGmailOAuthState(server: FastifyInstance, userId: string, organizationId: string): string {
  const nonce = crypto.randomBytes(16).toString('hex');
  const claims: GmailOAuthStateClaims = { sub: userId, orgId: organizationId, nonce, purpose: STATE_PURPOSE };
  return server.jwt.sign(claims, { expiresIn: `${STATE_TTL_SECONDS}s` });
}

export interface VerifiedGmailOAuthState {
  userId: string;
  organizationId: string;
}

/**
 * Verifies the state's signature and expiry (via the same JWT mechanism
 * that protects real user sessions), then atomically claims its nonce so
 * the same state token can never be consumed twice. Throws OAuthStateError
 * for every rejection case — missing, malformed, expired, bad signature,
 * or replayed — the caller should treat all of them identically (redirect
 * to the frontend's error state) rather than leaking which specific check
 * failed.
 */
export async function verifyAndConsumeGmailOAuthState(
  server: FastifyInstance,
  token: string | undefined | null
): Promise<VerifiedGmailOAuthState> {
  if (!token) {
    throw new OAuthStateError('Missing OAuth state');
  }

  let payload: unknown;
  try {
    payload = server.jwt.verify(token);
  } catch {
    throw new OAuthStateError('Invalid, expired, or tampered OAuth state');
  }

  if (
    typeof payload !== 'object' ||
    payload === null ||
    (payload as Partial<GmailOAuthStateClaims>).purpose !== STATE_PURPOSE ||
    typeof (payload as Partial<GmailOAuthStateClaims>).sub !== 'string' ||
    typeof (payload as Partial<GmailOAuthStateClaims>).orgId !== 'string' ||
    typeof (payload as Partial<GmailOAuthStateClaims>).nonce !== 'string'
  ) {
    throw new OAuthStateError('Malformed OAuth state payload');
  }

  const claims = payload as GmailOAuthStateClaims;

  const claimKey = `gmail_oauth_state_used:${claims.nonce}`;
  const claimed = await redis.set(claimKey, '1', 'EX', STATE_TTL_SECONDS, 'NX');
  if (claimed !== 'OK') {
    throw new OAuthStateError('OAuth state has already been used');
  }

  return { userId: claims.sub, organizationId: claims.orgId };
}
