/**
 * Case-scoped narrative report — services/api/src/modules/case/case.routes.ts
 * (`/cases/:caseId/reports*`), backed by the `Report` Prisma model. Distinct
 * from `ForensicReport` (the email-centric generated PDF report handled by
 * ReportsPanel.tsx/getEmailReports): this is an analyst-authored note
 * attached to a case, not a system-generated artifact.
 *
 * `contentHtml` is the raw field name the backend stores, but nothing in
 * this codebase sanitizes it — the frontend must always render it as plain
 * text (never `dangerouslySetInnerHTML`) to avoid a stored-XSS surface.
 */
export interface CaseReport {
  id: string;
  caseId: string;
  title: string;
  contentHtml: string | null;
  storageKey: string | null;
  generatedById: string | null;
  createdAt: string;
}
