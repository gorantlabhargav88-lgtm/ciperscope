import { CiperscopeApiClient, ApiError } from '@ciperscope/api-client';
import { api } from './api';

export { ApiError };

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000/api/v1';

/**
 * Typed client for the Email Forensics vertical slice (and any future slice
 * that adopts it). Reuses the existing `api` singleton's organization-id
 * state and base URL rather than duplicating that logic, and dispatches the
 * same `auth:unauthorized` event `AuthProvider` already listens for
 * (see apps/web/src/lib/api.ts) so 401 handling stays centralized.
 */
export const apiClient = new CiperscopeApiClient({
  baseUrl: BASE_URL,
  getOrganizationId: () => api.getOrganizationId(),
  onUnauthorized: () => window.dispatchEvent(new CustomEvent('auth:unauthorized')),
});
