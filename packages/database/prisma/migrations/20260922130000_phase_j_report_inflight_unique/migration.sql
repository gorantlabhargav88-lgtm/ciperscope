-- Phase J: enforce at most one in-flight (QUEUED or GENERATING) forensic
-- report per email at the database level. A partial unique index (not
-- representable via Prisma's `@@unique` DSL) is the smallest, most robust
-- guard against a race between two concurrent POST /:emailId/reports
-- requests each passing an application-level "does one already exist?"
-- check before either has inserted — the second INSERT simply fails with a
-- unique-violation, which the API route catches and treats as "already
-- queued", returning the existing row instead of creating a duplicate.
CREATE UNIQUE INDEX "ForensicReport_emailId_inflight_unique"
  ON "ForensicReport" ("emailId")
  WHERE "status" IN ('QUEUED', 'GENERATING');
