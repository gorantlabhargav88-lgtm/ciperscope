/*
  Warnings:

  - You are about to drop the column `confidence` on the `MLInference` table. All the data in the column will be lost.
  - You are about to drop the column `modelIdentifier` on the `MLInference` table. All the data in the column will be lost.
  - Added the required column `organizationId` to the `MLInference` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "MLInference" DROP COLUMN "confidence",
DROP COLUMN "modelIdentifier",
ADD COLUMN     "artifactSha256" TEXT,
ADD COLUMN     "labelMappingVersion" TEXT,
ADD COLUMN     "modelName" TEXT,
ADD COLUMN     "modelScore" DOUBLE PRECISION,
ADD COLUMN     "modelVersion" TEXT,
ADD COLUMN     "organizationId" TEXT NOT NULL,
ADD COLUMN     "preprocessingVersion" TEXT,
ADD COLUMN     "serviceVersion" TEXT,
ADD COLUMN     "status" TEXT NOT NULL DEFAULT 'NOT_AVAILABLE',
ADD COLUMN     "tokenizerVersion" TEXT,
ALTER COLUMN "prediction" DROP NOT NULL;

-- CreateIndex
CREATE INDEX "MLInference_organizationId_idx" ON "MLInference"("organizationId");

-- AddForeignKey
ALTER TABLE "MLInference" ADD CONSTRAINT "MLInference_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
