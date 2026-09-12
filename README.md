# CiperScope

AI-POWERED EMAIL THREAT DETECTION, GEOLOCATION & FORENSIC INTELLIGENCE PLATFORM

SEE THE THREAT.
TRACE THE INFRASTRUCTURE.
PROTECT THE EVIDENCE.
PROVE ITS INTEGRITY.

## Architecture

CiperScope is a monorepo containing the following components:

- `apps/web`: React/Vite web application (Command Center & SOC)
- `apps/mobile`: Flutter mobile application
- `services/api`: Node.js Fastify API and Redis workers
- `services/ai`: Python FastAPI DistilBERT and Gemini service
- `packages/*`: Shared internal packages (UI, types, config)
- `infra/*`: Docker compose, database schema, and deployment scripts

## Getting Started

Prerequisites:
- Node.js 20+
- pnpm 10+
- Docker

1. Run `pnpm install` to install dependencies.
2. Run `docker-compose -f infra/docker/docker-compose.yml up -d` to start local infrastructure.
3. Run `pnpm dev` to start all applications and services locally.
