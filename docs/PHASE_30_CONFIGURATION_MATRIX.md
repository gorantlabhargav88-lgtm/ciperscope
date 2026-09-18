# CIPERSCOPE PHASE 30 CONFIGURATION MATRIX

| Variable | Required | Component | Example format | Secret? | Validation | Current status |
|---|---|---|---|---|---|---|
| DATABASE_URL | Yes | DB | postgresql://user:pass@host:5432/db | Yes | Prisma connection | Verified Offline |
| REDIS_URL | Yes | Cache/Queue | redis://localhost:6379 | Yes | Redis Client | Verified Offline |
| VIRUSTOTAL_API_KEY | No | CTI | alphanumeric string | Yes | Config validation | Not Configured |
| ABUSEIPDB_API_KEY | No | CTI | alphanumeric string | Yes | Config validation | Not Configured |
| JWT_SECRET | Yes | API | base64 or long string | Yes | Auth middleware | Configured |
