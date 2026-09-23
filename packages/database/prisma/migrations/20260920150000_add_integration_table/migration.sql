-- This table was originally created out-of-band (via `prisma db push`
-- against the dev database, not through a tracked migration) during the
-- Gmail integration phase, so it never had a migration of its own — the
-- very next migration (20260920160000_gmail_security_hardening) already
-- ALTERs it. `prisma migrate deploy` against a genuinely fresh database
-- (as CI does) fails without this: "relation \"Integration\" does not
-- exist". Reconstructed here from the current schema.prisma model, minus
-- the `status` column and its supporting unique index — those are added
-- by 20260920160000_gmail_security_hardening immediately after, exactly
-- as they were originally applied.

-- CreateTable
CREATE TABLE "Integration" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "accessToken" TEXT NOT NULL,
    "refreshToken" TEXT NOT NULL,
    "emailAddress" TEXT NOT NULL,
    "historyId" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Integration_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Integration_organizationId_provider_emailAddress_key" ON "Integration"("organizationId", "provider", "emailAddress");

-- AddForeignKey
ALTER TABLE "Integration" ADD CONSTRAINT "Integration_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
