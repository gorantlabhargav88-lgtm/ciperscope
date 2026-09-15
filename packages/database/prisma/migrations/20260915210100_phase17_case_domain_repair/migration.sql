-- DropForeignKey
ALTER TABLE "_CaseEmails" DROP CONSTRAINT "_CaseEmails_A_fkey";

-- DropForeignKey
ALTER TABLE "_CaseEmails" DROP CONSTRAINT "_CaseEmails_B_fkey";

-- AlterTable
ALTER TABLE "Email" ADD COLUMN     "caseId" TEXT;

-- DropTable
DROP TABLE "_CaseEmails";

-- CreateIndex
CREATE UNIQUE INDEX "Case_id_organizationId_key" ON "Case"("id", "organizationId");

-- CreateIndex
CREATE INDEX "Email_caseId_idx" ON "Email"("caseId");

-- AddForeignKey
ALTER TABLE "Email" ADD CONSTRAINT "Email_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "Case"("id") ON DELETE SET NULL ON UPDATE CASCADE;

