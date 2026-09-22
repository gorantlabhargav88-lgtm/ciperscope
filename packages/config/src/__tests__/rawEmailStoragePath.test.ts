import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import path from 'path';

/**
 * Phase 11 fix: services/api and services/worker each previously defaulted
 * LocalRawEmailStore to `path.resolve(process.cwd(), '.data/emails')`
 * independently. When the two processes are started from different working
 * directories (the normal case for this monorepo), a raw email the API
 * wrote was never found by the worker's parsing stage, causing every
 * manually-ingested email to fail with "Raw email object missing in
 * storage" before any analysis ran.
 *
 * `defaultRawEmailStoragePath` must resolve to one fixed, cwd-independent
 * location so both processes agree, and must be overridable via
 * RAW_EMAIL_STORAGE_PATH.
 */
describe('defaultRawEmailStoragePath', () => {
  const originalCwd = process.cwd();
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.resetModules();
    process.env.NODE_ENV = 'test';
    process.env.JWT_SECRET = 'a'.repeat(32);
    process.env.DATABASE_URL = 'postgresql://user:pass@localhost:5432/db';
    process.env.GMAIL_TOKEN_ENCRYPTION_KEY = 'b'.repeat(32);
    delete process.env.RAW_EMAIL_STORAGE_PATH;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });

  it('is identical regardless of process.cwd() when RAW_EMAIL_STORAGE_PATH is unset', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue(path.resolve(originalCwd, '..'));
    const fromServicesDir = (await import('../index')).defaultRawEmailStoragePath;

    vi.resetModules();
    vi.spyOn(process, 'cwd').mockReturnValue(originalCwd);
    const fromRepoRoot = (await import('../index')).defaultRawEmailStoragePath;

    expect(fromServicesDir).toBe(fromRepoRoot);
    expect(path.isAbsolute(fromServicesDir)).toBe(true);
  });

  it('honors an explicit RAW_EMAIL_STORAGE_PATH override', async () => {
    const override = path.resolve(originalCwd, 'custom-raw-email-dir');
    process.env.RAW_EMAIL_STORAGE_PATH = override;

    const { defaultRawEmailStoragePath } = await import('../index');

    expect(defaultRawEmailStoragePath).toBe(override);
  });
});
