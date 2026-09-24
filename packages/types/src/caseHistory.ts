/**
 * Case change-history / audit trail — GET /cases/:caseId/history
 * (services/api/src/modules/case/case.routes.ts). Narrower than
 * CaseTimelineEvent/ForensicTimelineEvent: only AuditLog rows recorded
 * directly against the Case resource itself (status/priority/assignment
 * changes), not the broader case-wide activity feed.
 */
export interface CaseHistoryActor {
  id: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
}

export interface CaseHistoryEntry {
  id: string;
  action: string;
  actorId: string | null;
  createdAt: string;
  metadata: Record<string, unknown> | null;
  /** Present when actorId is set and the user is still a member of the org. */
  actor?: CaseHistoryActor | null;
  /** Present only for CASE_ASSIGNED entries. */
  assignedUser?: CaseHistoryActor | null;
}
