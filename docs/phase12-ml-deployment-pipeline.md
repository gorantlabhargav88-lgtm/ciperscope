# ML Model Deployment Pipeline (Phase 12)

This document outlines the required CI/CD pipeline for deploying and pinning the vetted `.safetensors` ML artifact for CiperScope, ensuring supply chain security and mitigating execution of untrusted code.

## 1. Local Training & Fine-Tuning
- Training occurs in an isolated air-gapped or restricted environment.
- The base model (e.g., `distilbert-base-uncased`) is downloaded and frozen.
- Fine-tuning dataset consists of curated PHISHING, BEC, and BENIGN samples.

## 2. Artifact Export
- The final weights MUST be exported strictly as `.safetensors` (Pickle formats like `.bin` or `.pt` are strictly prohibited).
- The tokenizer configuration and vocab files are exported alongside.

## 3. Vetting and Cryptographic Hashing
- The generated `.safetensors` file is hashed via SHA-256.
- The hash is logged and signed by the security team.
- Example:
  ```bash
  sha256sum model.safetensors > model.safetensors.sha256
  ```

## 4. Pipeline Enforcement (CI/CD)
- A GitHub Action or GitLab CI pipeline uploads the artifact to a hardened, internal-only S3 bucket (`s3://ciperscope-ml-artifacts/`).
- The pipeline updates the `services/ml-worker/docker-compose.yml` or Kubernetes deployment manifest to pass the `EXPECTED_MODEL_SHA256` environment variable.

## 5. Runtime Verification
- At boot time, `ml-worker` downloads the artifact from the secure S3 bucket.
- Before loading the model into memory, `ml-worker` calculates the SHA-256 of the downloaded `.safetensors` file.
- If the hash does not match `EXPECTED_MODEL_SHA256`, the service fatals and refuses to start.
- `trust_remote_code=True` is explicitly disabled in the `transformers` pipeline.

## 6. Rollback
- Rollbacks are performed by reverting the deployment manifest to the previous `EXPECTED_MODEL_SHA256`.

## Next Steps
- Implement `scripts/deploy_model.sh` to automate Step 4.
- Update `ml-worker/main.py` to perform Step 5 at initialization.
