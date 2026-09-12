-- CreateEnum
CREATE TYPE ""IdempotencyOperationStatus"" AS ENUM ('PENDING', 'PROCESSING', 'SUCCEEDED', 'FAILED', 'RECONCILIATION_REQUIRED');

-- CreateTable
CREATE TABLE ""IdempotencyOperation"" (
    ""id"" TEXT NOT NULL,
    ""organizationId"" TEXT NOT NULL,
    ""operationKey"" TEXT NOT NULL,
    ""operationType"" TEXT NOT NULL,
    ""resourceId"" TEXT,
    ""status"" ""IdempotencyOperationStatus"" NOT NULL DEFAULT 'PENDING',
    ""resultReference"" TEXT,
    ""errorCode"" TEXT,
    ""errorMessage"" TEXT,
    ""attemptCount"" INTEGER NOT NULL DEFAULT 0,
    ""lockedUntil"" TIMESTAMP(3),
    ""createdAt"" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ""updatedAt"" TIMESTAMP(3) NOT NULL,
    ""completedAt"" TIMESTAMP(3),

    CONSTRAINT ""IdempotencyOperation_pkey"" PRIMARY KEY (""id"")
);

-- CreateIndex
CREATE INDEX ""IdempotencyOperation_organizationId_operationKey_idx"" ON ""IdempotencyOperation""(""organizationId"", ""operationKey"");

-- CreateIndex
CREATE UNIQUE INDEX ""IdempotencyOperation_organizationId_operationKey_resourceId_key"" ON ""IdempotencyOperation""(""organizationId"", ""operationKey"", ""resourceId"");
