# CiperScope ML Evaluation Benchmark

## Purpose
This directory contains the engineering validation benchmark for the CiperScope ML Classification Service. Its primary purpose is to provide a reproducible foundation for threshold analysis and regression testing of the pinned ML model against deterministic input formats.

**IMPORTANT: This benchmark is an engineering validation set and is not evidence of production-grade statistical performance.**

## Dataset Schema
The dataset is stored in `data/samples.json` using the following schema:
```json
{
  "id": "sample-XXX",
  "label": "LEGITIMATE" | "PHISHING_OR_SPAM",
  "subject": "string",
  "sender": "string",
  "replyTo": "string",
  "body": "string"
}
```

## Label Definitions
- `LEGITIMATE`: Benign emails representing normal business communication.
- `PHISHING_OR_SPAM`: Malicious or heavily promotional emails designed to deceive, defraud, or spam users.

## Model Identity
- **Model ID:** `spotproject/spot-distilbert-phishing`
- **Revision:** `fc409441b8bfe0bada834c464ee1b88f162a534d`
- **Scoring Semantics:** The model output represents the softmax probability of the `PHISHING_OR_SPAM` class (`softmax(logits)[1]`).

## Provenance
The initial dataset consists of **SYNTHETIC** examples specifically crafted to mirror structural properties of internal email and common phishing templates without containing real PII, credentials, or scraped copyrighted material.

## Limitations
- **Small-Sample Limitation:** The current dataset consists of a very small number of synthetic samples (20). It is statistically insignificant for estimating true real-world model accuracy across the entire customer base.
- **BEC Limitation:** This model and dataset do *not* explicitly support Business Email Compromise (BEC) detection. BEC-like attacks (e.g. executive impersonation wire fraud) are currently mapped to `PHISHING_OR_SPAM` as a proxy, but are unsupported natively by the model class structure.
- **Threshold Analysis Limitation:** Any thresholds empirically chosen based on this synthetic dataset should be treated as engineering baselines, not definitive security boundaries.
- **Spam vs Phishing Overlap:** The model treats spam and phishing as a single unified class.

## Dataset Validation and Separation
Before any authorized real-world data can be used for `THRESHOLD_CALIBRATION` or `FINAL_VALIDATION`, it must pass strict structural, privacy, and metadata authorization gates using `validate_dataset.py`.

### Separation Gate
To prevent evaluation leakage, Calibration and Final Validation datasets are strictly separated using cryptographic fingerprints:
- **Canonicalization Rule:** Extracts only strictly required schema fields (`id`, `label`, `subject`, `sender`, `replyTo`, `body`) in their exact provided list order. The records are serialized into JSON with deterministically sorted keys and compact whitespace separators.
- **Fingerprinting:** A deterministic SHA-256 hash is generated from this canonical representation.
- **Overlap Protection:** `validate_dataset.py` cross-checks record IDs across calibration and validation sets, rejecting any overlap to ensure independent holdouts.

**Limitations of Separation Mechanism:**
The fingerprint and ID overlap controls strictly identify *exact duplication*. They DO NOT replace human provenance/privacy review, nor do they natively detect semantic near-duplicates, campaign leakage, or temporal contamination.
