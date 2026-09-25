-- Org-wide Audit Log (GET /audit-log) lists AuditLog rows by organization
-- ordered by createdAt desc. This composite index lets that be a single
-- ordered index scan instead of a bitmap-AND of the pre-existing separate
-- ["organizationId"] and ["createdAt"] indexes.
CREATE INDEX "AuditLog_organizationId_createdAt_idx" ON "AuditLog"("organizationId", "createdAt");
