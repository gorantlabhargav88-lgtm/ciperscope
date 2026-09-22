/**
 * Shapes a ForensicReport row for API responses. `artifactLocation` is the
 * internal storage key for the generated PDF (same class of value as
 * Evidence.storageKey) and is never returned — callers fetch the artifact
 * via GET /reports/:reportId/download instead.
 */
export function toPublicForensicReport(report: {
  id: string;
  organizationId: string;
  emailId: string;
  status: string;
  reportVersion: string;
  generatedAt: Date | null;
  sha256: string | null;
  errorMessage: string | null;
  requestedById: string | null;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: report.id,
    organizationId: report.organizationId,
    emailId: report.emailId,
    status: report.status,
    reportVersion: report.reportVersion,
    generatedAt: report.generatedAt,
    sha256: report.sha256,
    errorMessage: report.errorMessage,
    requestedById: report.requestedById,
    createdAt: report.createdAt,
    updatedAt: report.updatedAt,
  };
}
