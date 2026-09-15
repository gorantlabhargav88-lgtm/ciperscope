# CiperScope ML Evaluation Benchmark

## Purpose
This directory contains the engineering validation benchmark for the CiperScope ML Classification Service. Its primary purpose is to provide a reproducible foundation for threshold analysis and regression testing of the pinned ML model against deterministic input formats.

**IMPORTANT: This benchmark is an engineering validation set and is not evidence of production-grade statistical performance.**

### 1. Expected Data Format
Input datasets must be provided as JSON arrays containing exactly the required record-level fields.

**A. Existing Required Record Fields**
- `id`: Unique identifier (string).
- `label`: Exactly `"LEGITIMATE"` or `"PHISHING_OR_SPAM"`.
- `subject`: The email subject line (string).
- `sender`: The sender email address (string).
- `replyTo`: The reply-to email address (string).
- `body`: The email body text (string).

**B. New Optional Leakage Metadata**
To support rigorous data separation, the following record-level metadata may be provided:
- `timestamp`: (string) UTC ISO-8601.
- `campaign_hash`: (string) SHA-256 hash.
- `sender_domain_hash`: (string) SHA-256 hash.
- `url_domain_hash`: (string) SHA-256 hash.

**C. Required Evidence Metadata**
- `labeling_method`: (string) e.g., "Manual", "Heuristic". External reference to the labeling process.
- `authorization_evidence_id`: (string) Required for Calibration/Validation. Reference to external evidence of authorization.
- `semantic_candidate_review_status`: (string) e.g., "NOT_REVIEWED". Required for Calibration/Validation. Advisory review status.

**C. Exact Timestamp Format**
Must be UTC ISO-8601.
Formats accepted: `YYYY-MM-DDTHH:MM:SSZ` or with fractional seconds `YYYY-MM-DDTHH:MM:SS.[0-9]+Z`.

**D. Exact Hash Format**
Must be exactly 64-character lowercase hexadecimal string (SHA-256).

**F. Purpose-Specific Requirements**
- `ENGINEERING_REGRESSION`: Only the existing core fields are required. Leakage metadata is strictly optional. `authorization_evidence_id` and `semantic_candidate_review_status` are optional.
- `THRESHOLD_CALIBRATION`: The dataset MUST include `timestamp`, `campaign_hash`, and `sender_domain_hash` to enable rigorous upstream separation control. `url_domain_hash` is OPTIONAL (to support legitimate URL-free records), but if supplied, it must strictly match the hash format. MUST include `authorization_evidence_id` and `semantic_candidate_review_status`.
- `FINAL_VALIDATION`: The dataset MUST include `timestamp`, `campaign_hash`, and `sender_domain_hash` to establish robust independence from the calibration dataset. `url_domain_hash` is OPTIONAL. MUST include `authorization_evidence_id` and `semantic_candidate_review_status`.

**G. Cross-Dataset Leakage Controls**
When validating a `THRESHOLD_CALIBRATION` split against a `FINAL_VALIDATION` split, the evaluator natively computes exact strict separation across the following dimensions:
- **Campaign Separation**: Intersection of `campaign_hash` values between datasets must be empty.
- **Sender-Domain Separation**: Intersection of `sender_domain_hash` values between datasets must be empty.
- **URL-Domain Separation**: For records where `url_domain_hash` exists, intersection between datasets must be empty. URL-free records correctly bypass this correlation without triggering a false positive.
- **Strict Temporal Separation**: `max(calibration timestamp) < min(final-validation timestamp)` is strictly enforced. The calibration dataset's latest event must strictly pre-date the validation dataset's earliest event.

**H. Important Limitations**
- Dataset-level `coverage_period` does not establish record-level temporal independence.
- URL-free records may legitimately omit `url_domain_hash`. The absence of `url_domain_hash` means the evaluator cannot perform URL-domain correlation for that record. It does NOT mean the record is URL-independent, campaign-independent, or automatically safe for holdout evaluation.
- These controls establish separation only for the metadata dimensions actually represented. They do not prove semantic campaign independence, detect semantic near duplicates, or establish complete real-world independence of datasets. Concentration reporting and semantic near-duplicate detection remain future work.

**I. Representativeness Warnings**
- The evaluator natively provides *descriptive* class and temporal distribution statistics, but these do NOT prove that the dataset is representative of real-world or future production threat landscapes.
- Ensuring true representativeness requires human-in-the-loop domain expertise and cannot be established by the evaluator alone.

### 2. Evaluator Usage

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

## Statistical Evidence Tooling
The evaluation toolkit incorporates a rigorous offline statistical evidence layer designed for advanced dataset analysis.

### A. Operational Threshold Selection
The evaluator sweeps across strict `score > threshold` probability boundaries (0.00 to 1.00 in 0.01 increments) and calculates the deterministic precision, recall, F1, FPR, and FNR to dynamically identify a metric-optimal candidate threshold. It does NOT automatically select or replace production threshold parameters.

### B. Score Distribution Reporting
The evaluator produces aggregate summary statistics across all prediction scores.
- **Standard Deviation Convention:** The reported standard deviation uses the **population** formula (dividing by N, not N-1).

### C. Probability Calibration Metrics
The statistical layer implements basic non-parametric calibration measurement:
- **Brier Score:** Evaluates mean squared error of probability predictions against actual labels.
- **Expected Calibration Error (ECE):** A 10-bin equal-width discretization method to measure deviation between empirical positive rates and mean predicted probabilities.
- **Reliability Data:** Deterministic output of lower bound, upper bound, bin counts, and empirical rates across the 10 defined probability distribution bins.

### D. Bootstrap Uncertainty Estimation
To quantify threshold variance across small or noisy test sets, metric point estimates are paired with statistical uncertainty bounds via random resampling with replacement.
- **Bootstrap parameters:** Deterministic random seed (`seed=42`), 1000 resamples (`n_resamples=1000`), generating 95% interval boundaries (`ci_level=0.95`).

### E. Distinction Between Computed Metrics and Production Threshold Validation
Computing Brier score, ECE, or confidence intervals does not by itself calibrate the model or establish a production threshold. An empirically observed high F1 or low ECE on calibration evidence is strictly a "metric computed". Authoritative implementation into FusionEngine requires business-level acceptance, and no programmatic mechanism exists to circumvent manual validation.
