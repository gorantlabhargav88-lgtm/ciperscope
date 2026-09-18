# Phase 26 SOC Demo Runbook

## Overview
This runbook configures SOC workspace capabilities natively via local simulation targets safely avoiding external connectivity hits.

## Steps

### 1. Initialization
1. Configure `DATABASE_URL` and `REDIS_URL` safely against local offline containers.
2. Ensure `VIRUSTOTAL_API_KEY` is not explicitly exported to preserve offline caching fallback tests locally.

### 2. Service Orchestration
1. Boot baseline instances mapping local volumes natively via docker.
2. Initialize `pnpm` workspaces routing explicit API bounds effectively.
3. Validate cache execution loops function properly avoiding unhandled rejections dynamically.

### 3. SOC Workspace Evaluation
1. Access `InvestigationWorkspace` via authenticated routing components.
2. Load offline mock `.eml` samples successfully.
3. Observe extraction bounds successfully decoupling `BullMQ` threads locally.
4. Verify local intelligence mapping logs offline status variables effectively.
