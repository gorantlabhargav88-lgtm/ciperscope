# Phase 25 SOC Demo Runbook

## Overview
This runbook structures demonstration environments securely via offline execution test flows.

## Steps

### 1. Initialization
1. Configure `DATABASE_URL` and `REDIS_URL` in `.env`.
2. Omit `VIRUSTOTAL_API_KEY` to test graceful API degradation.

### 2. Service Boot
1. Map docker networks safely: `docker-compose up -d`.
2. Boot all core internal applications: `pnpm run start`.
3. Verify Redis caching routines accept native schema allocations successfully without crashing on provider absences.

### 3. Scenario Triggers
1. Load internal SOC Workspace at port `3000`.
2. Trigger the Email Parsing routine mapping `Investigation` bounds synchronously.
3. Observe extraction logic decoupling API handlers natively offloading CTI lookups to background containers gracefully.
