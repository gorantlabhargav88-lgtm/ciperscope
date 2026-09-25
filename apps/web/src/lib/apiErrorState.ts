import { ApiError } from './apiClient';

export type ApiErrorKind = 'unauthorized' | 'forbidden' | 'network' | 'error';

export interface ClassifiedApiError {
  kind: ApiErrorKind;
  message: string;
}

// A browser `fetch()` call rejects with a plain TypeError (never an
// ApiError/HTTP response) when it cannot reach the server at all — DNS
// failure, connection refused (API process not running), CORS rejection,
// or the network being offline. The exact wording is runtime-specific
// ("Failed to fetch" in Chromium, "NetworkError when attempting to fetch
// resource" in Firefox, "Load failed" in Safari) but the TypeError type and
// this vocabulary are stable enough to detect reliably.
const NETWORK_ERROR_PATTERN = /failed to fetch|networkerror|load failed|network request failed/i;

/**
 * Maps a caught error from an apiClient call to a UI-displayable state,
 * shared by ChainOfCustody and CaseForensicTimeline so 401/403 handling
 * (including the backend's tenant-isolation 403s — see
 * services/api/src/plugins/rbac.ts) isn't duplicated or drifted between
 * components. Never invents a friendlier message than the backend gave
 * for anything other than the well-known auth/network cases.
 */
export function classifyApiError(err: unknown, context: string): ClassifiedApiError {
  if (err instanceof ApiError && err.status === 401) {
    return { kind: 'unauthorized', message: 'Session expired — please sign in again.' };
  }
  if (err instanceof ApiError && err.status === 403) {
    return { kind: 'forbidden', message: `You do not have permission to view this ${context}.` };
  }
  if (err instanceof TypeError && NETWORK_ERROR_PATTERN.test(err.message)) {
    return {
      kind: 'network',
      message: 'Cannot reach the CiperScope API. Confirm the API server is running and reachable, then try again.',
    };
  }
  return { kind: 'error', message: err instanceof Error ? err.message : `Failed to load ${context}.` };
}
