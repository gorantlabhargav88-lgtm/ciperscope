# Phase 7 Implementation Plan - Email Ingestion

## 1. Current Architecture
- **Database**: Prisma ORM in `packages/database`. The schema defines `Email`, `Evidence`, and `IdempotencyOperation`, but `Email` is missing critical fields for tenant isolation and deduplication.
- **API Engine**: Fastify in `services/api` with structured logging (`@ciperscope/logger`), request context propagation, and a custom RBAC plugin.
- **Workers/Queues**: BullMQ integration is scaffolded in `packages/queue`, ready to be used by a background worker service (`services/worker`).
- **Clients**: React web app (`apps/web`) and Flutter mobile app (`apps/mobile`), both having foundational "Email Analysis" pages/views ready to be connected to the backend.

## 2. Existing Reusable Components
- **Logging & Context**: `@ciperscope/logger` provides `runWithContext` which manages `requestId` across async boundaries.
- **Authentication**: JWT-based session management and the `rbacPlugin` in `services/api`.
- **Database Modles**: `Organization` (tenant boundaries), `IdempotencyOperation` (for durable async task management).
- **Queue System**: Pre-configured Redis connections and BullMQ wrappers in `packages/queue`.

## 3. Required Changes
### Answers to Architecture Questions:
- **A. Where should the Email model live?** `packages/database/prisma/schema.prisma`
- **B. What database changes are required?** Add `organizationId` for tenant isolation, `sha256` for unique hashes, and a unique constraint combining both.
- **C. Is there already a storage abstraction?** No.
- **D. If not, where should RawEmailStore live?** A new package: `packages/storage`.
- **E. Where should the ingestion service live?** `services/api/src/modules/email/ingestion.service.ts`
- **F. Where should the upload API endpoint live?** `services/api/src/modules/email/email.routes.ts`
- **G. How should BullMQ represent the ingestion job?** See Queue Design below.
- **H. How should requestId/traceId propagate?** Extract `requestId` from the Fastify request, embed it in the BullMQ job payload, and restore it via `runWithContext` in the worker.
- **I. How should durable idempotency be reused?** Use the `IdempotencyOperation` model keyed by `[organizationId, sha256]` to handle concurrent identical uploads safely.
- **J. How should tenant authorization be enforced?** By validating `request.user.organizationId` via the JWT/RBAC middleware, and explicitly including `organizationId` in all database reads/writes.
- **K. Which permissions are required?** A new permission, e.g., `email.upload` or `evidence.create`, must be added and verified.
- **L. How should .eml files be validated?** Strict `fastify-multipart` limits (e.g. 20MB) and MIME type validation (`message/rfc822`), rejecting unparsable or malformed files.
- **M. How should SHA-256 be calculated?** By piping the file upload stream through `crypto.createHash('sha256')` concurrently while streaming to storage.
- **N. How should duplicate emails be detected?** DB unique constraint on `[organizationId, sha256]` and handling the `PrismaClientKnownRequestError` gracefully.
- **O. How should raw email bytes be stored?** Streamed to Object Storage (e.g., S3 or MinIO) using a derived, safe storage key.
- **P. How should Gmail provider integration be abstracted?** By implementing an interface (e.g., `IEmailProvider`) in `packages/providers` that fetches raw `.eml` and feeds it to the same internal ingestion service as the API upload endpoint.
- **Q. What security risks exist around email ingestion?** See Security Design below.
- **R. What tests need to be added?** See Testing Strategy below.
- **S. What files will need to change?** `schema.prisma`, API routes, queue definitions, new `packages/storage` files, and Web/Mobile UI.

## 4. Database Design
We must update `packages/database/prisma/schema.prisma`.
- **Add to `Email`**:
  - `organizationId String`
  - `sha256 String`
  - `@@unique([organizationId, sha256])`
  - Relation to `Organization` model.
- **Add to `Permission`**:
  - Insert seed data/enum for `email.upload` or equivalent.

## 5. API Design
- **Path**: `POST /api/v1/emails/upload`
- **Middleware**: JWT Auth, RBAC (`email.upload`), Rate Limiting.
- **Payload**: `multipart/form-data` with one or more `.eml` files.
- **Response**: `202 Accepted` returning job IDs for polling, or `200 OK` if processed synchronously.

## 6. Storage Design
- Create `packages/storage` exposing a generic interface: `putObject`, `getObject`, `deleteObject`.
- The `RawEmailStore` will generate a storage key like: `tenant-${organizationId}/emails/${sha256}.eml`.
- The raw file is streamed directly to storage to minimize memory overhead.

## 7. Queue Design
- **Queue Name**: `email-processing`
- **Job Payload**: 
  ```ts
  {
    emailId: string;
    organizationId: string;
    storageKey: string;
    sha256: string;
    traceId: string; // Passed down from API requestId
  }
  ```
- **Worker**: The worker will pick up the job, restore the `traceId` into the logger context, and begin parsing (parsing logic is Phase 8).

## 8. Security Design
> [!WARNING]
> Email ingestion is high-risk due to user-provided file processing.

- **Path Traversal**: Ignored client-provided filenames. The storage key is strictly constructed using the `organizationId` and the calculated `sha256` hash.
- **Malicious Filenames**: Filenames are metadata-only in the database; they are stripped from storage paths.
- **Oversized Uploads**: Fastify multipart limits set (e.g., `fileSize: 20 * 1024 * 1024`).
- **MIME Spoofing**: Validate the magic bytes/structure as a valid RFC822 format.
- **Raw Email Exposure**: S3 buckets should be private, accessed only via presigned URLs or backend streams.
- **Execution Risks (SSRF/HTML/JS)**: Do **NOT** fetch URLs, render HTML, or execute attachments during ingestion. The bytes remain strictly dormant data.

## 9. Authorization Design
Tenant isolation is non-negotiable. 
- API extracts `organizationId` from the authenticated user context.
- Database writes enforce `organizationId`.
- Queue payload explicitly includes `organizationId`.
- Worker strictly limits operations to the provided `organizationId`.
- S3 keys are prefixed with the `organizationId` (logical isolation).

## 10. Idempotency Design
- A DB transaction creates an `IdempotencyOperation` using `[organizationId, sha256]`.
- If an upload occurs with a matching hash, the system gracefully skips the duplicate upload, returning the existing `Email` metadata and skipping the storage write and queue placement.

## 11. Testing Strategy
- **Storage**: Unit tests for the S3 abstraction (mocked aws-sdk).
- **API**: Integration tests for `POST /api/v1/emails/upload` simulating multipart boundaries, oversized files, and invalid mime types.
- **Idempotency**: E2E test verifying that two rapid concurrent uploads of the same `.eml` file only result in one database record and one queue job.
- **Queue**: Verify that jobs are created with the correct `traceId` and `organizationId`.

## 12. Implementation Order
1. Update `schema.prisma` and run DB migration.
2. Create `packages/storage` and wire up the S3/MinIO client.
3. Update `packages/queue` to define the new `email-processing` queue and job types.
4. Implement the `ingestion.service.ts` in the API.
5. Implement the Fastify `email.routes.ts` with multipart parsing and RBAC.
6. Connect the React web app `EmailAnalysis.tsx` to the new upload API.
7. Connect the Flutter app `email_analysis` view to the new upload API.

## 13. Risks
- Memory exhaustion if multipart streaming is not handled correctly (e.g., buffering large files in RAM instead of streaming to storage/hash calculator).
- Dead letters in BullMQ if the database goes down during the worker phase.

## 14. Phase 8 Integration Points
- Phase 7 ends when the `.eml` is in object storage, the database `Email` record is created (status pending), and the `email-processing` job is in the queue.
- Phase 8 will implement the BullMQ worker that pulls the raw bytes from storage, parses the headers/body using a robust library (like `mailparser`), and writes the structured data to `EmailHeader`, `EmailAttachment`, etc.
