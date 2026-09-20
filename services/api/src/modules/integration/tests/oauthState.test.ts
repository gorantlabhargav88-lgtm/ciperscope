import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import { issueGmailOAuthState, verifyAndConsumeGmailOAuthState, OAuthStateError } from '../oauthState';

describe('Gmail OAuth state (issue + verify + consume)', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = Fastify();
    server.register(fastifyJwt, { secret: 'test-oauth-state-secret' });
    await server.ready();
  });

  afterAll(async () => {
    await server.close();
  });

  it('a freshly issued state is valid and returns the correct user/org', async () => {
    const token = issueGmailOAuthState(server, 'user-1', 'org-1');
    const result = await verifyAndConsumeGmailOAuthState(server, token);
    expect(result).toEqual({ userId: 'user-1', organizationId: 'org-1' });
  });

  it('missing state is rejected', async () => {
    await expect(verifyAndConsumeGmailOAuthState(server, undefined)).rejects.toThrow(OAuthStateError);
    await expect(verifyAndConsumeGmailOAuthState(server, '')).rejects.toThrow(OAuthStateError);
  });

  it('malformed state (not a valid JWT at all) is rejected', async () => {
    await expect(verifyAndConsumeGmailOAuthState(server, 'not-a-jwt')).rejects.toThrow(OAuthStateError);
  });

  it('a state signed with a different secret (invalid signature) is rejected', async () => {
    const otherServer = Fastify();
    otherServer.register(fastifyJwt, { secret: 'a-completely-different-secret' });
    await otherServer.ready();
    const forgedToken = issueGmailOAuthState(otherServer, 'attacker', 'attacker-org');
    await expect(verifyAndConsumeGmailOAuthState(server, forgedToken)).rejects.toThrow(OAuthStateError);
    await otherServer.close();
  });

  it('an expired state is rejected', async () => {
    const expiredToken = server.jwt.sign(
      { sub: 'user-1', orgId: 'org-1', nonce: 'expired-nonce-test', purpose: 'gmail_oauth_state' },
      { expiresIn: '1ms' }
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    await expect(verifyAndConsumeGmailOAuthState(server, expiredToken)).rejects.toThrow(OAuthStateError);
  });

  it('a state token is single-use: replaying the exact same token a second time is rejected', async () => {
    const token = issueGmailOAuthState(server, 'user-2', 'org-2');
    const first = await verifyAndConsumeGmailOAuthState(server, token);
    expect(first.userId).toBe('user-2');
    await expect(verifyAndConsumeGmailOAuthState(server, token)).rejects.toThrow(OAuthStateError);
  });

  it('a well-formed but wrong-purpose payload is rejected (defense in depth against JWT confusion)', async () => {
    const wrongPurposeToken = server.jwt.sign(
      { sub: 'user-3', orgId: 'org-3', nonce: 'wrong-purpose-nonce', purpose: 'something_else' } as any,
      { expiresIn: '10m' }
    );
    await expect(verifyAndConsumeGmailOAuthState(server, wrongPurposeToken)).rejects.toThrow(OAuthStateError);
  });

  it('two different states for two different users/orgs are each independently valid and isolated', async () => {
    const tokenA = issueGmailOAuthState(server, 'user-a', 'org-a');
    const tokenB = issueGmailOAuthState(server, 'user-b', 'org-b');
    const resultA = await verifyAndConsumeGmailOAuthState(server, tokenA);
    const resultB = await verifyAndConsumeGmailOAuthState(server, tokenB);
    expect(resultA).toEqual({ userId: 'user-a', organizationId: 'org-a' });
    expect(resultB).toEqual({ userId: 'user-b', organizationId: 'org-b' });
  });
});
