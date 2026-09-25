/**
 * Single source of truth for the permission `action` strings enforced by
 * `services/api/src/plugins/rbac.ts`'s `requirePermission()` hook.
 *
 * `Permission.action` in the Prisma schema is a free-form `String` (there is
 * no Prisma enum for it), so this manifest is the application-level
 * equivalent: seed scripts and tests import it instead of hardcoding the
 * list separately, so seeded data and route enforcement cannot silently
 * drift apart again.
 *
 * If you add a new `server.requirePermission('X')` call site in
 * `services/api`, add `'X'` here too and re-seed.
 */
export const SYSTEM_ENFORCED_PERMISSIONS = [
  { action: 'CASE_CREATE', description: 'Create cases' },
  { action: 'CASE_READ', description: 'Read cases' },
  { action: 'CASE_UPDATE', description: 'Update case fields and status' },
  { action: 'CASE_ASSIGN', description: 'Assign a case to a user' },
  { action: 'CASE_LINK_EMAIL', description: 'Link or unlink an email to a case' },
  { action: 'CASE_ADD_NOTE', description: 'Add, update, or delete case notes' },
  { action: 'CASE_MANAGE_EVIDENCE', description: 'Upload or delete case evidence' },
  { action: 'EMAIL_INGEST', description: 'Upload and ingest raw emails' },
  { action: 'EMAIL_READ', description: 'Read parsed email forensic data' },
  { action: 'ALERT_READ', description: 'Read alerts' },
  { action: 'ALERT_UPDATE', description: 'Update alert status' },
  { action: 'INVESTIGATION_READ', description: 'Read investigations' },
  { action: 'EVIDENCE_READ', description: 'Read evidence records' },
  { action: 'INTEGRATION_MANAGE', description: 'Connect, view, and disconnect third-party integrations (e.g. Gmail)' },
  { action: 'AUDIT_LOG_READ', description: 'Read the organization-wide audit log' },
  { action: 'USER_READ', description: 'Read organization members and roles' },
  { action: 'USER_MANAGE', description: 'Add, remove, and change the role/status of organization members' },
] as const;

export type SystemEnforcedPermission = (typeof SYSTEM_ENFORCED_PERMISSIONS)[number];
export type PermissionAction = SystemEnforcedPermission['action'];
