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

  it('a network-level TypeError (API unreachable) is classified as network, never shown as raw "Failed to fetch"', () => {
    const result = classifyApiError(new TypeError('Failed to fetch'), 'chain of custody');
    expect(result.kind).toBe('network');
    expect(result.message).not.toBe('Failed to fetch');
    expect(result.message).toMatch(/cannot reach the ciperscope api/i);
  });

  it('recognizes Firefox/Safari network-error wording too', () => {
    expect(classifyApiError(new TypeError('NetworkError when attempting to fetch resource.'), 'x').kind).toBe('network');
    expect(classifyApiError(new TypeError('Load failed'), 'x').kind).toBe('network');
  });

  it('a non-network TypeError still falls back to the generic error path', () => {
    const result = classifyApiError(new TypeError('Cannot read properties of undefined'), 'chain of custody');
    expect(result.kind).toBe('error');
    expect(result.message).toBe('Cannot read properties of undefined');
  });

  it('a completely unknown thrown value does not throw and falls back to a safe message', () => {
    const result = classifyApiError('not an Error object', 'case timeline');
    expect(result.kind).toBe('error');
    expect(result.message).toBe('Failed to load case timeline.');
  });
});
