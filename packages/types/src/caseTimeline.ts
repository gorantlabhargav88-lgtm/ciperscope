/**
 * Case-level forensic timeline contract.
 *
 * Backend mapping: GET /cases/:caseId/timeline
 * (services/api/src/modules/case/case.routes.ts:1166-1264) queries
 * `AuditLog` rows where `resource = 'Case'` and `resourceId = caseId`.
 *
 * IMPORTANT — this is a real but NARROW dataset: it is the case's own
 * audit trail (creation, updates, assignment, notes, email link/unlink,
 * evidence add/view/delete, report create/delete, alert view/update,
 * investigation create/view/update/intelligence-view, analyst decisions),
 * not a unified cross-system timeline. Email-level events (ingestion,
 * authentication, ML classification, CTI enrichment) are logged against
 * `resource: 'Email'` with the emailId, not the caseId, so they do NOT
 * appear here — do not merge them in or imply they do.
 */
export interface CaseTimelineEvent {
  id: string;
  action: string;
  actorId: string | null;
  createdAt: string;
  metadata: Record<string, unknown> | null;
}
