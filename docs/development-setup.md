# CiperScope Development Setup

## Prerequisites
- **Node.js**: v20 or later
- **pnpm**: v10+ (`npm install -g pnpm`)
- **Docker**: Docker Desktop must be installed and running.

## Environment Configuration
1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` and configure your environment variables. **Do not commit this file.**
   - `JWT_SECRET` must be set to a secure, random 256-bit+ string.
   - `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` should be set if using RS256/ES256.
   - Set up `DATABASE_URL` pointing to your local PostgreSQL Docker container.

## Local Services (Docker)
CiperScope requires PostgreSQL and Redis. Start them using Docker Compose:
```bash
docker compose -f infra/docker/docker-compose.yml up -d
```

## Database Initialization
Once Docker is running, initialize the Prisma schema:
```bash
# Push schema to database
pnpm --filter @ciperscope/database run db:push

# Generate Prisma Client
pnpm --filter @ciperscope/database run db:generate

# Optional: Seed the database with demo data
pnpm --filter @ciperscope/database run db:seed
```

## Running the API
We use `Turborepo` for monorepo task execution. To start the development server for all apps/services:
```bash
pnpm dev
```
Alternatively, to run just the API:
```bash
pnpm --filter @ciperscope/api run dev
```

## Security Rules
- **Never commit secrets**. Always use `.env`.
- Ensure all new environment variables are validated in `services/api/src/config/env.ts` using Zod.
