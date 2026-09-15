-- DropForeignKey
ALTER TABLE "Email" DROP CONSTRAINT "Email_caseId_fkey";

-- DropIndex
DROP INDEX "Email_caseId_idx";

-- AlterTable
ALTER TABLE "Case" ADD COLUMN     "assignedUserId" TEXT,
ADD COLUMN     "creatorId" TEXT,
ADD COLUMN     "resolvedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "Email" DROP COLUMN "caseId";

-- CreateTable
CREATE TABLE "_CaseEmails" (
    "A" TEXT NOT NULL,
    "B" TEXT NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "_CaseEmails_AB_unique" ON "_CaseEmails"("A", "B");

-- CreateIndex
CREATE INDEX "_CaseEmails_B_index" ON "_CaseEmails"("B");

-- CreateIndex
CREATE INDEX "Case_organizationId_assignedUserId_idx" ON "Case"("organizationId", "assignedUserId");

-- CreateIndex
CREATE INDEX "Case_organizationId_status_idx" ON "Case"("organizationId", "status");

-- CreateIndex
CREATE INDEX "Case_organizationId_priority_idx" ON "Case"("organizationId", "priority");

-- CreateIndex
CREATE INDEX "Case_organizationId_createdAt_idx" ON "Case"("organizationId", "createdAt");

-- AddForeignKey
ALTER TABLE "Case" ADD CONSTRAINT "Case_creatorId_fkey" FOREIGN KEY ("creatorId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Case" ADD CONSTRAINT "Case_assignedUserId_fkey" FOREIGN KEY ("assignedUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CaseEmails" ADD CONSTRAINT "_CaseEmails_A_fkey" FOREIGN KEY ("A") REFERENCES "Case"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CaseEmails" ADD CONSTRAINT "_CaseEmails_B_fkey" FOREIGN KEY ("B") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

