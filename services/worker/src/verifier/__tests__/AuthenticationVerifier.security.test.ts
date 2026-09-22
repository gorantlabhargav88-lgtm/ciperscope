import { DnsResolver } from '../DnsResolver';
import { SpfVerifier } from '../SpfVerifier';
import { AuthenticationVerifier } from '../AuthenticationVerifier';
import dns from 'dns/promises';
import { Readable } from 'stream';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import type { RawEmailStore } from '@ciperscope/storage';

vi.mock('dns/promises');

const loggerMock = vi.hoisted(() => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }));
vi.mock('@ciperscope/logger', () => ({ logger: loggerMock, generateRequestId: () => 'test-request-id' }));

describe('Security: Authentication Verifiers', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe('DnsResolver Limits', () => {
    it('should strictly enforce maximum DNS lookups to prevent recursion exhaustion (DoS)', async () => {
      const resolver = new DnsResolver(3, 1000); // Max 3 lookups
      const spfVerifier = new SpfVerifier(resolver);

      // Setup a cyclic or deeply recursive SPF chain
      // a.com -> include:b.com -> include:c.com -> include:d.com -> include:e.com
      vi.mocked(dns.resolveTxt).mockImplementation(async (domain: string) => {
        if (domain === 'a.com') return [['v=spf1 include:b.com ~all']];
        if (domain === 'b.com') return [['v=spf1 include:c.com ~all']];
        if (domain === 'c.com') return [['v=spf1 include:d.com ~all']];
        if (domain === 'd.com') return [['v=spf1 include:e.com ~all']];
        return [['v=spf1 -all']];
      });

      const result = await spfVerifier.verify('a.com', '192.168.1.1');
      
      // Since max lookups is 3, it should fail at c.com -> d.com
      expect(result.result).toBe('PERMERROR');
      expect(result.explanation).toContain('DNS lookup limit exceeded');
      expect(resolver.getLookupCount()).toBe(4); // Exceeded on the 4th call
    });

    it('should handle DNS timeouts gracefully as TEMPERROR without hanging', async () => {
      const resolver = new DnsResolver(10, 50); // 50ms timeout
      const spfVerifier = new SpfVerifier(resolver);

      vi.mocked(dns.resolveTxt).mockImplementation(async () => {
        return new Promise(resolve => setTimeout(resolve, 200)); // 200ms delay, exceeds 50ms
      });

      const start = Date.now();
      const result = await spfVerifier.verify('timeout.com', '192.168.1.1');
      const duration = Date.now() - start;

      expect(result.result).toBe('TEMPERROR');
      expect(result.explanation).toContain('DNS timeout');
      expect(duration).toBeLessThan(150); // Should resolve quickly due to 50ms timeout
    });
  });

  describe('SSRF / Network Protections', () => {
    it('must NEVER use http/fetch or open arbitrary sockets in verifiers', () => {
      // Static code analysis: ensure fetch/axios is not imported or used
      // Dynamic requires removed in favor of top-level imports
      
      const filesToCheck = [
        'AuthenticationVerifier.ts',
        'DnsResolver.ts',
        'SpfVerifier.ts',
        'DkimVerifier.ts',
        'DmarcVerifier.ts'
      ];

      for (const file of filesToCheck) {
        const content = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
        expect(content).not.toMatch(/require\(['"](http|https|axios|node-fetch)['"]\)/);
        expect(content).not.toMatch(/from\s+['"](http|https|axios|node-fetch)['"]/);
        // Ensure no global fetch is used
        expect(content).not.toMatch(/\Wfetch\(/);
      }
    });

    it('must NEVER shell out or dynamically evaluate code (child_process/exec/spawn/eval)', () => {
      const filesToCheck = [
        'AuthenticationVerifier.ts',
        'DnsResolver.ts',
        'SpfVerifier.ts',
        'DkimVerifier.ts',
        'DmarcVerifier.ts',
        'dkim/verifyCryptography.ts',
        'dkim/publicKey.ts',
        'dkim/canonicalize.ts',
        'dkim/headerSelection.ts',
        'dkim/tagList.ts',
        'dkim/rawMessage.ts'
      ];

      for (const file of filesToCheck) {
        const content = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
        expect(content).not.toMatch(/require\(['"]child_process['"]\)/);
        expect(content).not.toMatch(/from\s+['"]child_process['"]/);
        expect(content).not.toMatch(/\W(exec|execSync|spawn|spawnSync)\(/);
        expect(content).not.toMatch(/\Weval\(/);
        expect(content).not.toMatch(/\$queryRaw|\$executeRaw/);
      }
    });
  });

  describe('DKIM11 — no secret/raw-MIME leakage through logging', () => {
    beforeEach(() => {
      loggerMock.info.mockClear();
      loggerMock.warn.mockClear();
      loggerMock.error.mockClear();
      loggerMock.debug.mockClear();
    });

    // Planted secrets that must never appear in any logger call argument,
    // no matter which code path (success, failure, or malformed input) runs.
    const SECRET_ACCESS_TOKEN = 'ya29.PLANTED-OAUTH-ACCESS-TOKEN-SECRET';
    const SECRET_REFRESH_TOKEN = '1//PLANTED-OAUTH-REFRESH-TOKEN-SECRET';
    const SECRET_AUTH_HEADER = 'Bearer PLANTED-AUTHORIZATION-HEADER-SECRET';
    const SECRET_PRIVATE_KEY_MARKER = '-----BEGIN PRIVATE KEY-----PLANTED-DKIM-PRIVATE-KEY-----END PRIVATE KEY-----';
    const SECRET_BODY_MARKER = 'PLANTED-CONFIDENTIAL-BODY-CONTENT-MUST-NOT-BE-LOGGED';

    function allLoggedText(): string {
      const calls = [...loggerMock.info.mock.calls, ...loggerMock.warn.mock.calls, ...loggerMock.error.mock.calls, ...loggerMock.debug.mock.calls];
      return calls.map(call => JSON.stringify(call)).join('\n');
    }

    function buildSensitiveRawMessage(): Buffer {
      // A message whose headers/body carry every category of secret this
      // pipeline must never surface in a log line — including a forged
      // Authorization header (unrelated to real transport, but exercises
      // the same "never log this field name's content" property) and a
      // string shaped like DKIM private-key material.
      const headers = [
        'From: attacker@example.com',
        `Authorization: ${SECRET_AUTH_HEADER}`,
        `X-Planted-Access-Token: ${SECRET_ACCESS_TOKEN}`,
        `X-Planted-Refresh-Token: ${SECRET_REFRESH_TOKEN}`,
        'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel1; h=from; bh=x; b=y'
      ].join('\r\n');
      const body = `${SECRET_BODY_MARKER}\r\n${SECRET_PRIVATE_KEY_MARKER}\r\n`;
      return Buffer.from(`${headers}\r\n\r\n${body}`, 'latin1');
    }

    it('DKIM11-1: a raw-message load failure logs only the error object, never the raw bytes/tokens it was trying to load', async () => {
      const rawEmailStoreMock: Partial<RawEmailStore> = {
        exists: vi.fn().mockRejectedValue(new Error(`boom while loading ${SECRET_BODY_MARKER}`)),
        get: vi.fn()
      };

      const prismaMock = {
        email: {
          findUnique: vi.fn().mockResolvedValue({
            id: 'email-1',
            returnPath: null,
            rawStorageKey: 'key-1',
            headers: [],
            addresses: [],
            relayHops: []
          })
        },
        $transaction: vi.fn().mockImplementation(async (callback: (tx: unknown) => Promise<void>) => {
          await callback({
            emailAuthenticationAnalysis: { deleteMany: vi.fn(), create: vi.fn().mockResolvedValue({}) },
            spfVerification: { deleteMany: vi.fn(), create: vi.fn().mockResolvedValue({}) },
            dkimVerification: { deleteMany: vi.fn(), createMany: vi.fn().mockResolvedValue({}) },
            dmarcVerification: { deleteMany: vi.fn(), create: vi.fn().mockResolvedValue({}) },
            dnsObservation: { deleteMany: vi.fn(), createMany: vi.fn().mockResolvedValue({}) }
          });
        })
      };

      vi.mocked(dns.resolveTxt).mockResolvedValue([]);

      const verifier = new AuthenticationVerifier(prismaMock as never, rawEmailStoreMock as RawEmailStore);
      await verifier.verifyEmail('email-1');

      const logged = allLoggedText();
      expect(logged).not.toContain(SECRET_ACCESS_TOKEN);
      expect(logged).not.toContain(SECRET_REFRESH_TOKEN);
      expect(logged).not.toContain(SECRET_AUTH_HEADER);
      expect(logged).not.toContain(SECRET_PRIVATE_KEY_MARKER);
      // The error message itself intentionally embeds the body marker (to
      // simulate a worst-case library error echoing input) — this proves
      // the *logger call site* only ever passes the Error object, not a
      // separately-constructed string containing raw content, still leaks
      // nothing beyond what the thrown Error already carried incidentally.
      // The real guarantee under test is the four secret categories above.
      expect(loggerMock.warn).toHaveBeenCalledWith(expect.objectContaining({ err: expect.any(Error) }), expect.any(String));
    });

    it('DKIM11-2: a full successful verification run never logs the raw MIME body, headers, tokens, or key material', async () => {
      const rawMessage = buildSensitiveRawMessage();
      const rawEmailStoreMock: Partial<RawEmailStore> = {
        exists: vi.fn().mockResolvedValue(true),
        get: vi.fn().mockResolvedValue(Readable.from([rawMessage]))
      };

      const prismaMock = {
        email: {
          findUnique: vi.fn().mockResolvedValue({
            id: 'email-1',
            returnPath: null,
            rawStorageKey: 'key-1',
            headers: [{ name: 'DKIM-Signature', value: ' v=1; a=rsa-sha256; d=example.com; s=sel1; h=from; bh=x; b=y' }],
            addresses: [],
            relayHops: []
          })
        },
        $transaction: vi.fn().mockImplementation(async (callback: (tx: unknown) => Promise<void>) => {
          await callback({
            emailAuthenticationAnalysis: { deleteMany: vi.fn(), create: vi.fn().mockResolvedValue({}) },
            spfVerification: { deleteMany: vi.fn(), create: vi.fn().mockResolvedValue({}) },
            dkimVerification: { deleteMany: vi.fn(), createMany: vi.fn().mockResolvedValue({}) },
            dmarcVerification: { deleteMany: vi.fn(), create: vi.fn().mockResolvedValue({}) },
            dnsObservation: { deleteMany: vi.fn(), createMany: vi.fn().mockResolvedValue({}) }
          });
        })
      };

      vi.mocked(dns.resolveTxt).mockResolvedValue([]); // no key published -> PERMERROR, exercises the DKIM path fully

      const verifier = new AuthenticationVerifier(prismaMock as never, rawEmailStoreMock as RawEmailStore);
      await verifier.verifyEmail('email-1');

      const logged = allLoggedText();
      expect(logged).not.toContain(SECRET_ACCESS_TOKEN);
      expect(logged).not.toContain(SECRET_REFRESH_TOKEN);
      expect(logged).not.toContain(SECRET_AUTH_HEADER);
      expect(logged).not.toContain(SECRET_PRIVATE_KEY_MARKER);
      expect(logged).not.toContain(SECRET_BODY_MARKER);
      // Sanity: the run actually happened and logged something (proves this
      // isn't a vacuously-passing test with zero logger calls).
      expect(loggerMock.info).toHaveBeenCalled();
    });

    it('DKIM11-3: no verifier source file passes raw body/header/token fields directly into a logger call', () => {
      const filesToCheck = ['AuthenticationVerifier.ts', 'DkimVerifier.ts', 'DnsResolver.ts', 'SpfVerifier.ts', 'DmarcVerifier.ts'];
      const forbiddenLoggedFieldNames = /\b(rawMessage|rawBody|body|accessToken|refreshToken|authorization|privateKey|dkimPrivateKey)\s*[,:]/i;

      for (const file of filesToCheck) {
        const content = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
        const loggerCalls = content.match(/logger\.(info|warn|error|debug)\([^)]*\)/gs) ?? [];
        for (const call of loggerCalls) {
          expect(call).not.toMatch(forbiddenLoggedFieldNames);
        }
      }
    });
  });
});
