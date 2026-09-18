# Phase 23 Release Runbook

## Overview
This runbook provides initialization controls for production deployments, verifying the end-to-end viability of the SOC workflow in a safe manner.

## Steps

### 1. Environment Setup
1. Validate PostgreSQL 15+ & Redis infrastructure limits in `.env` variables.
2. Initialize containers securely via: `docker-compose up -d --build`.

### 2. Service Verification
1. Boot application modules via `pnpm run start`.
2. Inspect `AuditLog` outputs matching standard startup signatures cleanly without generating API timeout cascades.

### 3. Scenario Execution
1. Open the internal `InvestigationWorkspace`.
2. Map a synthetic Email threat event input safely.
3. Validate IOC normalizations extract domains correctly to trigger BullMQ tasks asynchronously.
4. If API keys for CTI providers are not set, expect intelligence states to render naturally as degraded/unavailable caching fallbacks.
5. Trace visual geolocation mapping results natively matching the source IP address headers extracted.
