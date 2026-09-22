-- AlterEnum
ALTER TYPE "UrlExtractionSource" ADD VALUE 'QR_CODE';

-- AlterTable
ALTER TABLE "EmailAttachment" ADD COLUMN     "qrFindings" JSONB;

