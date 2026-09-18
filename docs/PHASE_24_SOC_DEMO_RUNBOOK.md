# Phase 24 SOC Demo Runbook

## Overview
This runbook structures demonstration environments securely via simulated test payloads designed to avoid live credential consumption.

## Steps

### 1. Initialization
1. Start infrastructure natively: `docker-compose up -d`.
2. Configure `.env` mappings explicitly tracking Redis instances without specifying `VIRUSTOTAL_API_KEY`.

### 2. Service Boot
1. Boot standard package modules: `pnpm run start`.
2. Assert 0 Typescript warnings.

### 3. Execution Verification
1. Access `InvestigationWorkspace` through internal frontend routing.
2. Load a standard offline threat test (e.g. `test_relay_anomaly.eml`).
3. Verify extraction vectors process domains without hanging the UI synchronously.
4. Observe caching loops cleanly resolve external intelligence into "Not Configured" limits locally, proving BullMQ operates autonomously outside UI threads.
5. Record analyst judgments successfully updating PostgreSQL `Investigation` tables natively.
