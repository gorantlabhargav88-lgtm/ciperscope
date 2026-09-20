import { ApiError } from './apiClient';

export type ApiErrorKind = 'unauthorized' | 'forbidden' | 'error';

export interface ClassifiedApiError {
  kind: ApiErrorKind;
  message: string;
}

/**
 * Maps a caught error from an apiClient call to a UI-displayable state,
 * shared by ChainOfCustody and CaseForensicTimeline so 401/403 handling
 * (including the backend's tenant-isolation 403s — see
 * services/api/src/plugins/rbac.ts) isn't duplicated or drifted between
 * components. Never invents a friendlier message than the backend gave
 * for anything other than the two well-known auth cases.
 */
export function classifyApiError(err: unknown, context: string): ClassifiedApiError {
  if (err instanceof ApiError && err.status === 401) {
    return { kind: 'unauthorized', message: 'Session expired — please sign in again.' };
  }
  if (err instanceof ApiError && err.status === 403) {
    return { kind: 'forbidden', message: `You do not have permission to view this ${context}.` };
  }
  return { kind: 'error', message: err instanceof Error ? err.message : `Failed to load ${context}.` };
}
