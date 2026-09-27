# CipherScope Production Deployment Guide

This document specifies the deployment architecture, configuration guidelines, infrastructure setup, and operational runbooks for deploying the CipherScope Threat Intelligence & Email Forensics Platform to production.

---

## 1. System Architecture

CipherScope is architected as an enterprise-grade microservice monorepo:

```
[ Inbound Email / Web Client ]
       │
       ▼
[ Web Frontend (SPA) ] ── (HTTPS / REST + SSE) ──> [ API Gateway / Fastify Service ]
                                                          │            │
                                       ┌──────────────────┘            └──────────────────┐
                                       ▼                                                  ▼
                            [ Managed PostgreSQL ]                             [ Managed Redis / BullMQ ]
                                       ▲                                                  ▲
                                       │                                                  │
                                       └──────────────────┬───────────────────────────────┘
                                                          ▼
                                            [ Background Worker Service ]
                                              ├── Forensic Analyzers
                                              ├── CTI & Geolocation (MaxMind/AbuseIPDB)
                                              ├── ML Classifier (DistilBERT Python Service)
                                              └── Blockchain Anchoring Engine (Sepolia / EVM)
```

### Production Service Roles
- **Frontend SPA**: Static asset distribution via CDN or Node/Nginx edge server (e.g. Cloudflare Pages, Vercel, AWS S3/CloudFront, or Docker Nginx).
- **Backend API (`services/api`)**: High-throughput Fastify server running in clustered or containerized Node 20+ runtime behind HTTPS reverse proxy.
- **Worker (`services/worker`)**: BullMQ consumer processing email pipelines (`email-processing`, `email-authentication`, `email-threat-analysis`, `email-cti-enrichment`, `email-ml-classification`, `gmail-sync`).
- **ML Inference (`services/ml-worker`)**: Python FastAPI container executing DistilBERT transformer models.
- **Data Persistence**: Managed PostgreSQL (v15+) with persistent SSD volumes.
- **Queue/Broker**: Managed Redis (v7+) with AOF/RDB persistence.

---

## 2. Prerequisites & Required Infrastructure

| Service | Recommended Spec (Production) | Minimum Version |
| :--- | :--- | :--- |
| **Node.js** | LTS (Node 20.x or 22.x) | 20.0.0+ |
| **pnpm** | v9+ / v10+ | 9.0.0+ |
| **PostgreSQL** | 2 vCPU, 4GB RAM (Managed RDS/Cloud SQL) | 15.x |
| **Redis** | 2 vCPU, 2GB RAM (Managed ElastiCache/Memorystore) | 7.x |
| **Python** | 3.10+ (for ML worker service) | 3.10.x |
| **Docker** | Engine 24.x+, Compose v2.20+ | 24.0.0+ |

---

## 3. Environment Variables Reference

A `.env.example` file is maintained in the repository root. Ensure the following production values are configured in your secret management system:

### Core Configuration
- `NODE_ENV`: Set to `production`.
- `PORT`: Default `3000` (API listening port).
- `WORKER_PORT`: Default `3001` (Worker metrics & health check port).
- `CORS_ORIGIN`: Exact production frontend origins (comma-separated, e.g. `https://app.cipherscope.io,https://cipherscope.io`).

### Database & Redis
- `DATABASE_URL`: Production PostgreSQL URI (`postgresql://USER:PASSWORD@HOST:5432/ciperscope_db?sslmode=require&schema=public`).
- `REDIS_URL`: Production Redis URI (`rediss://:PASSWORD@HOST:6379` with TLS).

### Security & Tokens
- `JWT_SECRET`: Cryptographically random string (min 32 characters, preferably 64 hex characters).
- `JWT_ISSUER`: `ciperscope-auth`
- `JWT_AUDIENCE`: `ciperscope-web`
- `GMAIL_TOKEN_ENCRYPTION_KEY`: 32-byte hex key for AES-256-GCM token encryption at rest.

### Threat Intelligence & Geolocation (Optional / Recommended)
- `VIRUSTOTAL_API_KEY`: Enterprise/Public API key.
- `ABUSEIPDB_API_KEY`: API key for IP abuse reporting.
- `MAXMIND_ACCOUNT_ID` & `MAXMIND_LICENSE_KEY`: GeoIP2 City web service credentials.
- `RDAP_ENABLED`: `true` to enable outbound RDAP queries.

### ML Service & Blockchain
- `ML_SERVICE_URL`: URL to the ML service (`http://ml-worker:8000` or private VPC endpoint).
- `ML_SERVICE_TOKEN`: Bearer token for inter-service communication.
- `BLOCKCHAIN_ENABLED`: `true` (enables EVM anchoring).
- `BLOCKCHAIN_NETWORK`: `sepolia` (or `mainnet`).
- `BLOCKCHAIN_RPC_URL`: JSON-RPC endpoint (e.g. Infura / Alchemy).
- `BLOCKCHAIN_CONTRACT_ADDRESS`: Address of deployed `CipherScopeAnchor` contract.
- `BLOCKCHAIN_PRIVATE_KEY`: Gas wallet private key (managed via HSM or Vault).

---

## 4. Production Database Setup & Migration

### Migration Strategy
Do **NOT** use `prisma migrate dev` or `prisma db push` in production. Always execute `prisma migrate deploy` to apply verified migrations:

```bash
# In CI/CD or deployment container before service start:
pnpm --filter @ciperscope/database exec prisma migrate deploy
```

### Seeding Initial Roles & Permissions
Run the idempotent seed script to establish the required system permissions and default roles:

```bash
pnpm --filter @ciperscope/database db:seed
```

---

## 5. Deployment Procedures

### A. Deploying the Backend API
1. Build the production application:
   ```bash
   pnpm --filter @ciperscope/api build
   ```
2. Start the API server:
   ```bash
   node services/api/dist/index.js
   ```
3. Verify health check:
   ```bash
   curl -f http://localhost:3000/health
   # Expected response: {"status":"ok","timestamp":"..."}
   ```

### B. Deploying the Background Worker
1. Build the worker package:
   ```bash
   pnpm --filter @ciperscope/worker build
   ```
2. Start the worker:
   ```bash
   node services/worker/dist/index.js
   ```
3. Worker will automatically establish connections to Postgres and Redis, and begin consuming from BullMQ queues.

### C. Deploying the Frontend SPA
1. Configure build-time environment variable:
   ```bash
   export VITE_API_URL="https://api.cipherscope.io/api/v1"
   ```
2. Run production build:
   ```bash
   pnpm --filter web build
   ```
3. Deploy the resulting `apps/web/dist` directory to your static hosting platform. Ensure all fallback routes direct to `index.html` for client-side routing.

---

## 6. Integrations Configuration

### Gmail OAuth 2.0 & Pub/Sub
1. In the Google Cloud Console, configure an OAuth 2.0 Web Client.
2. Set Authorized Redirect URI:
   `https://api.cipherscope.io/api/v1/integrations/gmail/callback`
3. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.
4. Configure Pub/Sub topic permissions allowing `gmail-api-push@system.gserviceaccount.com` to publish notifications to `GOOGLE_PUBSUB_TOPIC`.

### Blockchain Sepolia Anchoring
1. Compile smart contracts:
   ```bash
   npx tsx infra/blockchain/scripts/compile.ts
   ```
2. Deploy contract to target EVM network:
   ```bash
   npx tsx infra/blockchain/scripts/deploy.ts
   ```
3. Set `BLOCKCHAIN_CONTRACT_ADDRESS` to the deployed contract address.
4. Verify provider integration:
   ```bash
   pnpm --filter @ciperscope/providers test
   ```

---

## 7. Health Checks & Monitoring

| Endpoint | Method | Expected Code | Purpose |
| :--- | :--- | :--- | :--- |
| `/health` | `GET` | 200 OK | Process liveness & readiness check |
| `/api/v1/auth/session` | `GET` | 200 / 401 | Authenticated gateway check |
| `:3001/metrics` | `GET` | 200 OK | Prometheus performance metrics |

---

## 8. Rollback & Disaster Recovery

1. **Database Rollbacks**: Use point-in-time recovery (PITR) on managed PostgreSQL. Schema migrations should always be backwards-compatible (additive changes first).
2. **Application Rollbacks**: Revert container image tags or Git release commits and redeploy previous stable artifacts.
3. **Queue Drain**: In the event of worker outage, BullMQ retains unacknowledged jobs in Redis with exponential backoff retry.
