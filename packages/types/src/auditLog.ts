/**
 * Organization-wide Audit Log — GET /audit-log
 * (services/api/src/modules/audit/audit.routes.ts). Same AuditLog table as
 * CaseHistoryEntry (caseHistory.ts), without the Case-resource narrowing.
 * Safe-field-only: never carries ipAddress/userAgent or unscrubbed
 * metadata — logAuditEvent() already redacts sensitive metadata keys at
 * write time (services/api/src/utils/audit.ts).
 */
export interface AuditLogActor {
  id: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
}

export interface AuditLogEntry {
  id: string;
  action: string;
  resource: string;
  resourceId: string | null;
  status: string;
  createdAt: string;
  actorId: string | null;
  /** Present when actorId is set and the user is still a member of the org. */
  actor: AuditLogActor | null;
  metadata: Record<string, unknown> | null;
}

export interface AuditLogListResponse {
  items: AuditLogEntry[];
  nextCursor: string | null;
}
