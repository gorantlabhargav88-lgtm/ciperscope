# Calibration Dataset Intake Specification

This document provides the intake specification and template for processing an explicitly authorized real-world calibration and final-validation dataset.

**CURRENT STATUS: NO AUTHORIZED CALIBRATION DATASET AVAILABLE**
- Do NOT perform threshold calibration.
- Do NOT modify production ML/runtime behavior.
- Do NOT change FusionEngine thresholds.
- Do NOT claim representativeness or production readiness.
- The 0.40 and 0.85 values remain engineering reference thresholds, NOT empirically calibrated production thresholds.

## Dataset Structure

### A. Calibration Dataset
**Purpose:** `THRESHOLD_CALIBRATION`

### B. Final Validation Dataset
**Purpose:** `FINAL_VALIDATION`

### Required Record Fields
- `id`
- `label` (Allowed labels: `LEGITIMATE`, `PHISHING_OR_SPAM`)
- `subject`
- `sender`
- `replyTo`
- `body`

### Required Calibration/Final Metadata
- `authorized_for_ml_evaluation`: boolean
- `privacy_review_status`: "APPROVED"
- `provenance_verified`: boolean
- `authorization_evidence_id`: string
- `labeling_method`: string
- `timestamp`: UTC ISO-8601 ending in Z
- `campaign_hash`: 64-character lowercase SHA-256
- `sender_domain_hash`: 64-character lowercase SHA-256
- `semantic_candidate_review_status`: `NOT_REVIEWED`, `REVIEWED_NO_LEAKAGE`, or `REVIEWED_POTENTIAL_LEAKAGE`

### Optional Metadata
- `url_domain_hash`: 64-character lowercase SHA-256
- `labeling_evidence_id`: string

## Provider Checklist (Engineering Intake)

Before accepting an authorized dataset, verify the following (this is an engineering checklist, not a legal claim):
- [ ] Lawful/organizational authorization obtained.
- [ ] Privacy approval ("APPROVED") granted.
- [ ] Provenance established and verified.
- [ ] Labeling methodology defined.
- [ ] Collection period documented.
- [ ] Class distribution documented (descriptive only).
- [ ] Dataset ownership/access clearly defined.
- [ ] Retention restrictions specified.
- [ ] Explicit permission to process raw email content.
- [ ] Explicit permission to use data for ML evaluation.
- [ ] An independent final-validation holdout is provided.

## Separation Requirements
Calibration and final-validation datasets must be separated by:
- ID
- Canonical fingerprint
- `campaign_hash`
- `sender_domain_hash`
- `url_domain_hash` (when available)
- Strict temporal ordering (`max(calibration.timestamp) < min(final_validation.timestamp)`)

Semantic near-duplicate detection is advisory and requires human review.

## Privacy
- Do not persist unnecessary raw email data.
- Hashes are used for leakage metadata.
- IDs are used in evaluation output (no email body/subject in output).
- Semantic candidate output contains IDs and similarity only.

## Future Validation Procedure
Run the dataset validation using the existing CLI tool (Do NOT execute this until an authorized dataset is provided):
```bash
python -m services.ml-worker.eval.validate_dataset \
    --cal-data path/to/cal.json \
    --cal-metadata path/to/cal_meta.json \
    --val-data path/to/val.json \
    --val-metadata path/to/val_meta.json
```

## Template Data Example (Non-Operational)
```json
[
  {
    "id": "<EMAIL_ID>",
    "label": "<LABEL>",
    "subject": "<SUBJECT>",
    "sender": "<SENDER>",
    "replyTo": "<REPLY_TO>",
    "body": "<BODY>",
    "timestamp": "<TIMESTAMP>",
    "campaign_hash": "<CAMPAIGN_HASH>",
    "sender_domain_hash": "<SENDER_DOMAIN_HASH>",
    "semantic_candidate_review_status": "<STATUS>"
  }
]
```
