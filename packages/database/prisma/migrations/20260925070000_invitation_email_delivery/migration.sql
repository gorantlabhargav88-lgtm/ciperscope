-- Real email delivery for invitations (packages/providers/src/email):
-- track delivery status separately from the invitation's own lifecycle,
-- and record the resend supersession chain.
-- CreateEnum
CREATE TYPE "InvitationEmailStatus" AS ENUM ('NOT_CONFIGURED', 'SENT', 'FAILED');

-- AlterTable
ALTER TABLE "Invitation" ADD COLUMN     "emailError" TEXT,
ADD COLUMN     "emailStatus" "InvitationEmailStatus" NOT NULL DEFAULT 'NOT_CONFIGURED',
ADD COLUMN     "supersedesId" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "Invitation_supersedesId_key" ON "Invitation"("supersedesId");

-- AddForeignKey
ALTER TABLE "Invitation" ADD CONSTRAINT "Invitation_supersedesId_fkey" FOREIGN KEY ("supersedesId") REFERENCES "Invitation"("id") ON DELETE SET NULL ON UPDATE CASCADE;
