import { describe, it, expect } from 'vitest';
import { ApiError } from './apiClient';
import { classifyApiError } from './apiErrorState';

describe('classifyApiError', () => {
  it('401 is classified as unauthorized with a session-expired message', () => {
    const result = classifyApiError(new ApiError(401, 'Invalid or missing token'), 'case timeline');
    expect(result.kind).toBe('unauthorized');
    expect(result.message).toMatch(/sign in again/i);
  });

  it('403 (including a tenant-isolation violation from rbac.ts) is classified as forbidden', () => {
    const result = classifyApiError(new ApiError(403, 'Tenant isolation violation'), 'case timeline');
    expect(result.kind).toBe('forbidden');
    expect(result.message).toContain('case timeline');
  });

  it('a generic API failure (e.g. 500) is classified as error and surfaces the backend message', () => {
    const result = classifyApiError(new ApiError(500, 'Internal Server Error'), 'chain of custody');
    expect(result.kind).toBe('error');
    expect(result.message).toBe('Internal Server Error');
  });

  it('a network-level error (not an ApiError) falls back to a generic context message', () => {
    const result = classifyApiError(new TypeError('Failed to fetch'), 'chain of custody');
    expect(result.kind).toBe('error');
    expect(result.message).toBe('Failed to fetch');
  });

  it('a completely unknown thrown value does not throw and falls back to a safe message', () => {
    const result = classifyApiError('not an Error object', 'case timeline');
    expect(result.kind).toBe('error');
    expect(result.message).toBe('Failed to load case timeline.');
  });
});
