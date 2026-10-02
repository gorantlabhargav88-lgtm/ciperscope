-- Phase 32: persist email pipeline dispatch intent independently from
-- Email.analysisStatus so queue outages and process restarts are recoverable.
CREATE TYPE "EmailDispatchState" AS ENUM ('PENDING', 'DISPATCHING', 'DISPATCHED');

CREATE UNIQUE INDEX "Email_id_organizationId_key" ON "Email"("id", "organizationId");

CREATE TABLE "EmailDispatchOutbox" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "stage" TEXT NOT NULL,
    "eventKey" TEXT NOT NULL,
    "queueName" TEXT NOT NULL,
    "jobName" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "state" "EmailDispatchState" NOT NULL DEFAULT 'PENDING',
    "attemptCount" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "claimedAt" TIMESTAMP(3),
    "claimToken" TEXT,
    "lockedUntil" TIMESTAMP(3),
    "dispatchedAt" TIMESTAMP(3),
    "lastError" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EmailDispatchOutbox_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "EmailDispatchOutbox_eventKey_key" ON "EmailDispatchOutbox"("eventKey");
CREATE UNIQUE INDEX "EmailDispatchOutbox_organizationId_emailId_stage_key" ON "EmailDispatchOutbox"("organizationId", "emailId", "stage");
CREATE INDEX "EmailDispatchOutbox_state_nextAttemptAt_createdAt_idx" ON "EmailDispatchOutbox"("state", "nextAttemptAt", "createdAt");
CREATE INDEX "EmailDispatchOutbox_organizationId_state_nextAttemptAt_idx" ON "EmailDispatchOutbox"("organizationId", "state", "nextAttemptAt");

ALTER TABLE "EmailDispatchOutbox" ADD CONSTRAINT "EmailDispatchOutbox_organizationId_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "EmailDispatchOutbox" ADD CONSTRAINT "EmailDispatchOutbox_emailId_organizationId_fkey"
    FOREIGN KEY ("emailId", "organizationId") REFERENCES "Email"("id", "organizationId") ON DELETE CASCADE ON UPDATE CASCADE;
