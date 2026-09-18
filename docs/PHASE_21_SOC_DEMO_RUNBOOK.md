# Phase 21 SOC Demo Runbook

## Overview
This runbook guides administrators through a fully verified end-to-end simulated SOC investigation flow on CiperScope without exposing real credentials or victim identifiers.

## Steps

### 1. Environment Setup
1. Duplicate `.env.example` to `.env`. Do NOT commit.
2. Initialize Docker instances via `docker-compose up -d`.

### 2. Startup Verification
1. Boot backend via `pnpm run dev`.
2. Ensure Postgres and Redis respond to worker heartbeats without hanging.

### 3. Scenario Execution
1. Navigate to the frontend SOC client. 
2. Submit a Synthetic Test Email file (`test_malformed_phish.eml`).
3. View the automatic parsed results. Validate that IOC hashes are intercepted perfectly.
4. Wait `20-30s` for BullMQ to enrich indicators via Redis cache / API fallback.
5. Review the resulting Investigation Workspace interface:
   - Identify extracted GeoLocation topologies.
   - Trace relay hops against extracted threat metrics.
   - Register Analyst verdict (e.g. `REVIEWED`, `ESCALATED`).
6. Validate that `AuditLog` captures the escalation successfully.
