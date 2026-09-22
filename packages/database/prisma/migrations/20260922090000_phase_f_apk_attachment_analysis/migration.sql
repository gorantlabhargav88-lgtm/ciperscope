-- Phase F: attachment/APK static analysis
-- Adds two nullable JSON columns to EmailAttachment to hold structured,
-- deterministic findings (threatIndicators) and APK-specific static
-- metadata (apkMetadata) when the attachment is identified as an APK.
-- Purely additive and backward-compatible: existing rows get NULL, no
-- existing column, index, or constraint is touched.
ALTER TABLE "EmailAttachment" ADD COLUMN "threatIndicators" JSONB;
ALTER TABLE "EmailAttachment" ADD COLUMN "apkMetadata" JSONB;
