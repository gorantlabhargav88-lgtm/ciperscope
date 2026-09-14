# Phase 11 Implementation Plan: DistilBERT AI/NLP Threat Classification

## 1. Current Architecture Findings
- **Monorepo**: TypeScript-based (Turbo, pnpm). Node.js services (`api`, `worker`).
- **Database**: PostgreSQL accessed via Prisma. The `MLInference` model exists for storing predictions.
- **Queue/Workers**: Robust BullMQ implementation (`QueueManager`, `IdempotencyManager`).
- **API Framework**: **Fastify** (verified in `services/api/package.json`).
- **Forensic Pipeline**: Preceding phases correctly identify forensic facts, auth results, and passive URL/Attachment context.

## 2. Phase 11 Goals
- Introduce a DistilBERT-based NLP classification layer strictly as a passive signal.
- Analyze email text to output structured `MODEL_PREDICTION`.
- Retain strict isolation of persistence logic (TypeScript) and inference logic (Python).

## 3. Explicit Non-Goals
- DO NOT replace deterministic forensics (SPF, signatures).
- DO NOT claim 100% malicious certainty ("this is definitely malicious").
- DO NOT train models on customer data dynamically in production.
- DO NOT use an untuned/base DistilBERT model as a threat classifier.

## Base vs fine-tuned model
A generic pretrained DistilBERT model is NOT a phishing/BEC classifier. The architecture explicitly separates the base pretrained model from a fine-tuned classification artifact. The production inference artifact MUST be a genuine sequence-classification model with a trained classification head, explicit label mapping, and evaluation metadata. Do not fabricate fake PHISHING/BEC/BENIGN predictions from an untuned base model.

## Model artifact availability
If a vetted existing DistilBERT-based security classification model (Option A) or a separately governed fine-tuned model (Option B) is not currently available, the system gracefully degrades. The inference engine is production-ready but explicitly returns `MODEL_STATUS = NOT_AVAILABLE` until a verified trained artifact is supplied.

## ML service architecture
The preferred runtime architecture is:
`TypeScript Worker -> internal authenticated inference request -> Python ML Inference Service -> DistilBERT Classification Model -> Prediction -> TypeScript Worker -> PostgreSQL / Prisma`.
The Python ML service is strictly inference-only.

## Internal service authentication
The Python ML service must:
- Listen only on an internal/private interface.
- Never be publicly exposed.
- Have no outbound internet access in production.
- Require service authentication.
- Enforce request-size limits, inference timeouts, and concurrency limits.
- Reject malformed requests.
- Never log email body or model input.
- Never execute arbitrary code from request content.

## Prediction contract
**Request (TS->Python)**:
- `request ID`
- `email ID`
- `organization ID` or tenant context
- `model input text` (minimum sanitized text only, no raw MIME)
- `preprocessing version`
- `requested model version`

**Response (Python->TS)**:
- `status`
- `predicted label`
- `score`
- `model name`
- `model version`
- `artifact SHA-256`
- `tokenizer version`
- `preprocessing version`
- `inference timestamp`
- `service version`

## Model artifact verification
Model artifacts must be loaded via `.safetensors`. We will pin the exact model revision/commit, artifact SHA-256, tokenizer revision, label mapping, and preprocessing version. No arbitrary downloading of model weights at runtime. Do NOT enable `trust_remote_code=True`. Pickle-based artifacts are strictly rejected. The artifact must be verified before loading.

## Persistence ownership
The Python ML service does NOT independently mutate the `MLInference` database record. The TypeScript worker retains absolute ownership over PostgreSQL persistence and orchestration, ensuring Prisma remains the sole database contract and tenant authorization remains centralized.

## Label compatibility
Initial taxonomy: `PHISHING`, `BEC`, `MALWARE_DELIVERY`, `BENIGN`, `INSUFFICIENT_CONFIDENCE`.
If the selected trained model has different labels, they will not be silently remapped. An explicit versioned label mapping will be created. If the model cannot reliably distinguish these classes, the limitation is documented rather than forced.

## Confidence semantics
Raw softmax output is NOT automatically calibrated probability. It is stored as `modelScore`. Predictions will not be labelled as "X% probability of phishing" without calibration. If the score is below the explicit and versioned threshold, the status resolves to `INSUFFICIENT_CONFIDENCE`.

## Failure/degraded modes
If inference fails: `FAILED`
If timeout: `TIMEOUT`
If model unavailable: `NOT_AVAILABLE`
If below confidence threshold: `INSUFFICIENT_CONFIDENCE`
No classifications are ever fabricated in degraded modes.

## Deployment model
Phase 10 completes and the TS worker creates an ML classification job on the Redis queue. The queue payload remains ID/reference based. The TS worker pulls the permitted model input immediately before inference and transmits it to the ML service over the internal authenticated boundary. The service runs locally within the isolated container network.

## Privacy
No raw email body in logs, metrics, traces, error messages, Redis, or model telemetry. Observability relies strictly on `emailId`, `organizationId`, and `requestId`.

## Input Pipeline & Truncation
- **Pipeline**: Use only the Subject, Sender identity, Reply-To (where available), and safe body text. Preserve forensic originals separately. Preprocessing is deterministic and versioned.
- **Truncation**: We will not blindly truncate to 512 tokens. A deterministic strategy prioritizes high-value email evidence: Subject, Sender identity, Reply-To, and the beginning of the body (where phishing context resides), followed by relevant body segments up to the tokenizer limit. Any truncation prioritized behavior will be explicitly documented.
