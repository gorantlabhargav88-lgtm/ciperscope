# Phase 11: DistilBERT AI/NLP Threat Classification

## Overview
Phase 11 introduces a production-ready, highly secure ML inference classification infrastructure designed to classify email texts (e.g. PHISHING, BEC, MALWARE_DELIVERY, BENIGN) via a fine-tuned DistilBERT model.

## Model Artifact Status
**AI CLASSIFICATION INFRASTRUCTURE READY**
**MODEL ARTIFACT: NOT AVAILABLE**
**PRODUCTION PREDICTION: DISABLED**

*Important*: A vetted, securely fine-tuned sequence classification model artifact currently DOES NOT EXIST in the environment.
- We DO NOT use an untuned base DistilBERT model.
- We DO NOT dynamically download arbitrary weights from Hugging Face.
- We DO NOT fabricate or spoof prediction results.
- We DO NOT train on production customer emails.

Because no model artifact is provided, the inference service currently utilizes the `UnavailableModelProvider`. All inference requests safely return `MODEL_STATUS = NOT_AVAILABLE`.

## Architecture
The system consists of two strictly bounded components:
1. **TypeScript Worker (BullMQ/Prisma)**: Owns orchestration, queue idempotency, and absolute persistence ownership. It queries permitted data, formats input, and calls the Python service.
2. **Python ML Service (FastAPI)**: Entirely stateless, isolated, and internal. Runs the PyTorch/Transformers inference pipeline based on deterministic inputs and returns structured schema responses.

## Model Caveats & Disclaimers
When a model is eventually introduced:
1. Model output is a **model prediction, not ground truth**.
2. Raw scores are **not calibrated probabilities**.
3. The model **does not prove attacker identity**.
4. The model **does not prove malicious intent**.
5. The model **does not prove compromise**.
6. The model **does not prove physical location**.
7. Authentication (Phase 9) and forensic evidence (Phase 8) remain strictly independent of ML classification.
