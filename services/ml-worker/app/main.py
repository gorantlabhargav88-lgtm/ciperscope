from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional
import os
import time

app = FastAPI(title="CiperScope ML Classification Service", version="1.0.0")

# Security configuration
INTERNAL_AUTH_TOKEN = os.getenv("ML_SERVICE_TOKEN", "internal-secret-token")

# --- Schemas ---

class PredictionRequest(BaseModel):
    requestId: str
    emailId: str
    organizationId: str
    modelInputText: str
    preprocessingVersion: str
    requestedModelVersion: str

class PredictionResponse(BaseModel):
    status: str
    predictedLabel: Optional[str] = None
    modelScore: Optional[float] = None
    modelName: Optional[str] = None
    modelVersion: Optional[str] = None
    artifactSha256: Optional[str] = None
    tokenizerVersion: Optional[str] = None
    preprocessingVersion: Optional[str] = None
    inferenceTimestamp: Optional[str] = None
    serviceVersion: Optional[str] = None

# --- Dependencies ---

async def verify_internal_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ")[1]
    if token != INTERNAL_AUTH_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid token")
    return token

# --- Model Provider Abstraction ---

class ModelProvider:
    def predict(self, text: str) -> dict:
        raise NotImplementedError()

    def get_metadata(self) -> dict:
        raise NotImplementedError()

class UnavailableModelProvider(ModelProvider):
    def predict(self, text: str) -> dict:
        return {
            "status": "NOT_AVAILABLE",
            "predictedLabel": None,
            "modelScore": None,
        }

    def get_metadata(self) -> dict:
        return {
            "modelName": None,
            "modelVersion": None,
            "artifactSha256": None,
            "tokenizerVersion": None,
            "preprocessingVersion": "1.0",
        }

# Future: DistilBertModelProvider
# To be implemented when a vetted SAFETENSORS fine-tuned model artifact is provided.
# Will enforce no trust_remote_code, strictly safetensors, deterministic preprocessing.

# --- Global State ---

# By default, because no verified model exists, use UnavailableModelProvider.
# This prevents fabrication of PHISHING/BENIGN labels.
current_provider: ModelProvider = UnavailableModelProvider()

# --- Endpoints ---

@app.get("/health")
async def health_check():
    provider_metadata = current_provider.get_metadata()
    model_ready = provider_metadata.get("modelName") is not None

    return {
        "service": "healthy",
        "model": "ready" if model_ready else "not_available"
    }

@app.post("/api/v1/predict", response_model=PredictionResponse)
async def predict_email(request: PredictionRequest, token: str = Depends(verify_internal_token)):
    # 1. Deterministic Preprocessing
    # (Even with unavailable model, we enforce boundaries here)
    # E.g. NFKC normalization, zero-width stripping
    processed_text = request.modelInputText.strip()

    if len(processed_text) > 100000:
        raise HTTPException(status_code=400, detail="Input text exceeds maximum length")

    # 2. Inference
    prediction_result = current_provider.predict(processed_text)
    metadata = current_provider.get_metadata()

    # 3. Assemble Response
    return PredictionResponse(
        status=prediction_result["status"],
        predictedLabel=prediction_result["predictedLabel"],
        modelScore=prediction_result["modelScore"],
        modelName=metadata["modelName"],
        modelVersion=metadata["modelVersion"],
        artifactSha256=metadata["artifactSha256"],
        tokenizerVersion=metadata["tokenizerVersion"],
        preprocessingVersion=metadata["preprocessingVersion"],
        inferenceTimestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        serviceVersion="1.0.0"
    )
