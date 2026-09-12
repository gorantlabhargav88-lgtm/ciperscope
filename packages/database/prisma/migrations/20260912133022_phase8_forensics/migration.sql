-- CreateEnum
CREATE TYPE "AnalysisState" AS ENUM ('PENDING', 'PROCESSING', 'COMPLETED', 'PARTIAL', 'FAILED');

-- AlterTable
ALTER TABLE "Email" ADD COLUMN     "analysisStatus" "AnalysisState" NOT NULL DEFAULT 'PENDING';

-- AlterTable
ALTER TABLE "EmailHeader" ADD COLUMN     "index" INTEGER NOT NULL DEFAULT 0;

-- AlterTable
ALTER TABLE "RelayHop" ADD COLUMN     "byHost" TEXT,
ADD COLUMN     "fromHost" TEXT,
ADD COLUMN     "parsedConfidence" DOUBLE PRECISION,
ADD COLUMN     "protocol" TEXT,
ADD COLUMN     "receivingHost" TEXT,
ADD COLUMN     "sendingHost" TEXT;

-- CreateTable
CREATE TABLE "MimePart" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "parentId" TEXT,
    "partIndex" TEXT NOT NULL,
    "contentType" TEXT NOT NULL,
    "contentDisposition" TEXT,
    "filename" TEXT,
    "contentId" TEXT,
    "contentLocation" TEXT,
    "transferEncoding" TEXT,
    "charset" TEXT,
    "sizeBytes" INTEGER,
    "isAttachment" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MimePart_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EmailAddress" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "headerName" TEXT NOT NULL,
    "displayName" TEXT,
    "address" TEXT,
    "localPart" TEXT,
    "domain" TEXT,
    "raw" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EmailAddress_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "MimePart_emailId_idx" ON "MimePart"("emailId");

-- CreateIndex
CREATE INDEX "EmailAddress_emailId_idx" ON "EmailAddress"("emailId");

-- AddForeignKey
ALTER TABLE "MimePart" ADD CONSTRAINT "MimePart_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MimePart" ADD CONSTRAINT "MimePart_parentId_fkey" FOREIGN KEY ("parentId") REFERENCES "MimePart"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EmailAddress" ADD CONSTRAINT "EmailAddress_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;
