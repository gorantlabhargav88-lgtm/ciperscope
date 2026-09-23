-- Phase I: give Evidence a first-class organizationId (denormalized from
-- case.organizationId, same rationale already used for ForensicReport) so
-- tenant isolation can be enforced directly on Evidence without a join
-- through Case, plus a sourceSystem provenance column.
ALTER TABLE "Evidence" ADD COLUMN "organizationId" TEXT;
ALTER TABLE "Evidence" ADD COLUMN "sourceSystem" TEXT;

UPDATE "Evidence" e
SET "organizationId" = c."organizationId"
FROM "Case" c
WHERE c.id = e."caseId";

ALTER TABLE "Evidence" ALTER COLUMN "organizationId" SET NOT NULL;

CREATE INDEX "Evidence_organizationId_idx" ON "Evidence"("organizationId");
