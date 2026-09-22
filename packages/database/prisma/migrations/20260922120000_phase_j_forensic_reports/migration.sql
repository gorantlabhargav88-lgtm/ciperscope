-- CreateEnum
CREATE TYPE "ForensicReportStatus" AS ENUM ('QUEUED', 'GENERATING', 'COMPLETED', 'FAILED');

-- CreateTable
CREATE TABLE "ForensicReport" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "status" "ForensicReportStatus" NOT NULL DEFAULT 'QUEUED',
    "reportVersion" TEXT NOT NULL DEFAULT '1.0',
    "generatedAt" TIMESTAMP(3),
    "artifactLocation" TEXT,
    "sha256" TEXT,
    "errorMessage" TEXT,
    "requestedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ForensicReport_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ForensicReport_organizationId_idx" ON "ForensicReport"("organizationId");

-- CreateIndex
CREATE INDEX "ForensicReport_emailId_idx" ON "ForensicReport"("emailId");

-- CreateIndex
CREATE INDEX "ForensicReport_organizationId_emailId_status_idx" ON "ForensicReport"("organizationId", "emailId", "status");

-- AddForeignKey
ALTER TABLE "ForensicReport" ADD CONSTRAINT "ForensicReport_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

