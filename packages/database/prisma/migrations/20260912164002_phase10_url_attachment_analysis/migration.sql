-- CreateEnum
CREATE TYPE "UrlExtractionSource" AS ENUM ('TEXT', 'HTML_HREF', 'HTML_SRC', 'HTML_ACTION', 'OTHER');

-- AlterTable
ALTER TABLE "EmailAttachment" ADD COLUMN     "actualMimeType" TEXT,
ADD COLUMN     "archiveMetadata" JSONB,
ADD COLUMN     "isArchive" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "isMismatch" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "magicBytes" TEXT;

-- AlterTable
ALTER TABLE "EmailUrl" ADD COLUMN     "indicators" JSONB,
ADD COLUMN     "isObfuscated" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "normalizedUrl" TEXT,
ADD COLUMN     "source" "UrlExtractionSource" NOT NULL DEFAULT 'TEXT';
