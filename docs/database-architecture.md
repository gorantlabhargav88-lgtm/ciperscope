# Database Architecture

## Overview
CiperScope utilizes PostgreSQL managed via Prisma ORM to provide a highly relational, structurally sound, and scalable data layer.

The schema design follows a strict multi-tenant architecture, separating logic into core domains:
1. Identity & RBAC
2. Case Management
3. Email Forensics
4. Threat Intelligence
5. Artificial Intelligence (DistilBERT/Gemini)
6. Blockchain Anchoring & Forensics

## Entity Relationship Model

### Multi-Tenancy
- **Organization**: The root tenant. All user activity occurs within the context of an Organization.
- **OrganizationMember**: Grants Users specific `Role` levels within an Organization.
- **Isolation Strategy**: Every Case, Alert, and Investigation is bound to an `Organization`. Shared threat intelligence (e.g., global IP reputations) exists at the system level.

### Forensics & Chain of Custody
- **Evidence**: Forensically preserved items. An Evidence record is strictly immutable (`Restrict` cascades).
- **ChainOfCustodyEvent**: A linked-list ledger recording every action taken on evidence (`COLLECTED`, `ANALYZED`, `EXPORTED`).
- **BlockchainAnchor**: A record containing the `transactionId` where the `SHA-256` hash of an `Evidence` object was committed to the Hyperledger Fabric network.

### Threat Intelligence Normalization
Instead of creating isolated tables for IP, Domain, or URL reputation, CiperScope uses a unified `Indicator` model.
- **Indicator**: Stores the IOC type (e.g., `DOMAIN`) and value.
- **ThreatIntelObservation**: Stores the polymorphic results from any intelligence provider (VirusTotal, PhishTank), preserving provider metadata and timestamps.

### AI Engine Data
- **MLInference**: Stores DistilBERT predictions for emails, preserving model version and latency.
- **RiskAssessment**: Calculates aggregated risk using `RiskFactor` signals (SPF failures, ML predictions).

## Indexing Strategy
To ensure query performance at scale:
- `@@index([organizationId])` on all tenant-bound tables to speed up multi-tenant scoping.
- Unique constraints on `Email.messageId` and `Indicator.value`.
- Time-based indexes on `AuditLog.createdAt` for fast timeline generation.
- Strict foreign key cascades (`Cascade` for safe relations like `Email` -> `EmailHeader`, `Restrict` for sensitive relations like `Case` -> `Evidence`).

## Seeding
A `seed.ts` file populates the development database with a simulated `Development Security Operations` organization, complete with sample cases, emails, and pending blockchain anchors for UI demonstration.

## Migration Workflow
1. Author changes in `schema.prisma`.
2. Run `pnpm db:format` and `pnpm db:validate`.
3. Apply locally using `pnpm db:migrate` (runs against the Dockerized PostgreSQL instance).
