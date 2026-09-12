# Authentication and RBAC Architecture

CiperScope uses a highly secure, centralized API-driven authentication system designed for both Web and Mobile (Flutter) clients.

## 1. Authentication Flow
- **Passwords**: Hashed securely using `Argon2id` (memory cost: 64MB, time cost: 3, parallelism: 4). Plaintext passwords are NEVER logged or stored.
- **Login Strategy**:
  - The client provides email/password.
  - Rate limiting protects the endpoint against brute-force attacks.
  - Generic errors (`Invalid email or password`) prevent account enumeration.
  - On success, the API issues two tokens:
    1. **Access Token (JWT)**: Short-lived (15m), containing minimal claims (`sub`, `orgs`, `sid`).
    2. **Refresh Token**: Long-lived (7d) opaque string.
- **Session Tracking**: A `Session` record is created per login, tracking device metadata and tying the access and refresh tokens to a single session that can be actively revoked.

## 2. Token Security & Transport
- **Web (React)**: Tokens are set as secure, HTTP-only, SameSite cookies. This prevents JavaScript access and minimizes XSS risk while `SameSite=strict` prevents CSRF.
- **Mobile (Flutter)**: Tokens are sent in the JSON payload. Flutter handles them via secure local storage (e.g., Keystore/Keychain).
- **Refresh Token Rotation**: Refresh tokens are opaque strings stored as Argon2 hashes in the DB (like passwords). Using a refresh token invalidates the old one and issues a new one. If an old token is reused, the entire session is immediately revoked (Token Theft Protection).

## 3. Multi-Tenancy & Tenant Isolation
- **Organization Context**: Every authenticated request must pass the `X-Organization-Id` header (unless the endpoint is globally open to System Admins).
- **Enforcement**: The `requirePermission` Fastify hook validates that the user's JWT `orgs` array includes the requested Organization ID, mathematically guaranteeing tenant isolation before the database is even hit.

## 4. Role-Based Access Control (RBAC)
- **Granular Permissions**: We shifted from a hardcoded Enum to a normalized `Permission` table (e.g., `evidence.verify`, `case.read`).
- **Roles**: Roles group permissions together. Roles can be system-wide (e.g., `SYSTEM_ADMIN`) or customized per Organization.
- **Authorization Middleware**: A custom Fastify decorator `fastify.requirePermission('action')` evaluates if the user's role in the specific organization context includes the required action.

## 5. Security & Audit Logging
All critical authentication flows (Login, Logout, Failed Login, Token Reuse, Permission Denied) automatically write to the `AuditLog` table, enriching the record with IP address and User-Agent data for forensic accountability.

## 6. Password Reset / Verification (Planned)
The database schema (`VerificationToken`) is prepared to support single-use, time-bound tokens for password resets and email verification, pending SMTP integration.
