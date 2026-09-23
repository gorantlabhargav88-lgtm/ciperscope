-- Phase M: evolve BlockchainAnchor from dead 1:1-per-evidence schema (zero
-- supporting code, confirmed in Phase I discovery) into a real per-batch
-- Merkle-root integrity record. Any pre-existing row is fabricated demo
-- seed data (a fake "PENDING" anchor with no real batch behind it) and is
-- removed rather than migrated — there is no real batch it could map to.
DELETE FROM "BlockchainAnchor";

-- AlterEnum
BEGIN;
CREATE TYPE "BlockchainAnchorStatus_new" AS ENUM ('HASHED', 'BATCHED', 'ANCHORED', 'NOT_CONFIGURED', 'FAILED');
ALTER TABLE "BlockchainAnchor" ALTER COLUMN "status" DROP DEFAULT;
ALTER TABLE "BlockchainAnchor" ALTER COLUMN "status" TYPE "BlockchainAnchorStatus_new" USING ("status"::text::"BlockchainAnchorStatus_new");
ALTER TYPE "BlockchainAnchorStatus" RENAME TO "BlockchainAnchorStatus_old";
ALTER TYPE "BlockchainAnchorStatus_new" RENAME TO "BlockchainAnchorStatus";
DROP TYPE "BlockchainAnchorStatus_old";
ALTER TABLE "BlockchainAnchor" ALTER COLUMN "status" SET DEFAULT 'HASHED';
COMMIT;

-- DropForeignKey
ALTER TABLE "BlockchainAnchor" DROP CONSTRAINT "BlockchainAnchor_evidenceId_fkey";

-- DropIndex
DROP INDEX "BlockchainAnchor_evidenceId_key";

-- DropIndex
DROP INDEX "BlockchainAnchor_transactionId_key";

-- AlterTable
ALTER TABLE "BlockchainAnchor" DROP COLUMN "anchorTimestamp",
DROP COLUMN "evidenceId",
ADD COLUMN     "anchoredAt" TIMESTAMP(3),
ADD COLUMN     "batchKey" TEXT NOT NULL,
ADD COLUMN     "evidenceCount" INTEGER NOT NULL,
ADD COLUMN     "evidenceIds" JSONB NOT NULL,
ADD COLUMN     "hashAlgorithm" TEXT NOT NULL DEFAULT 'SHA-256',
ADD COLUMN     "merkleRoot" TEXT NOT NULL,
ADD COLUMN     "organizationId" TEXT NOT NULL,
ALTER COLUMN "network" DROP NOT NULL,
ALTER COLUMN "network" DROP DEFAULT,
ALTER COLUMN "status" SET DEFAULT 'HASHED';

-- AlterTable
ALTER TABLE "ChainOfCustodyEvent" ADD COLUMN     "eventHash" TEXT;

-- AlterTable
ALTER TABLE "Evidence" ADD COLUMN     "anchorId" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "BlockchainAnchor_batchKey_key" ON "BlockchainAnchor"("batchKey");

-- CreateIndex
CREATE INDEX "BlockchainAnchor_organizationId_idx" ON "BlockchainAnchor"("organizationId");

-- CreateIndex
CREATE INDEX "Evidence_anchorId_idx" ON "Evidence"("anchorId");

-- AddForeignKey
ALTER TABLE "Evidence" ADD CONSTRAINT "Evidence_anchorId_fkey" FOREIGN KEY ("anchorId") REFERENCES "BlockchainAnchor"("id") ON DELETE SET NULL ON UPDATE CASCADE;
