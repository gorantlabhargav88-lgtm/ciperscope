-- Phase 7B: Gmail security hardening.
-- No existing Integration rows were present at migration authoring time
-- (verified live: `SELECT count(*) FROM "Integration"` = 0), so this is a
-- purely additive, non-destructive change with zero data-migration risk.

-- Track connection health so the sync worker can mark a connection ERROR
-- when Google permanently rejects the stored refresh token, and the
-- disconnect endpoint can mark it DISCONNECTED.
ALTER TABLE "Integration" ADD COLUMN "status" TEXT NOT NULL DEFAULT 'ACTIVE';

-- A given mailbox can only ever belong to one organization at a time. This
-- makes the Gmail webhook lookup (which Google's push-notification payload
-- identifies only by emailAddress, never by organizationId) safe: a
-- findUnique on (provider, emailAddress) can never return an ambiguous
-- cross-tenant match.
CREATE UNIQUE INDEX "Integration_provider_emailAddress_key" ON "Integration"("provider", "emailAddress");
