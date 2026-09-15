from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional
import os
import time
import logging
import asyncio
from contextlib import asynccontextmanager
from fastapi.concurrency import run_in_threadpool

# --- Global State ---
# We define current_provider at the top so the lifespan can reference it.
current_provider = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global current_provider
    # Initialize to Unavailable
    current_provider = UnavailableModelProvider()

    def load_model():
        global current_provider
        try:
            logging.info("Starting background model initialization...")
            provider = DistilBertModelProvider()
            if provider.is_ready:
                current_provider = provider
                logging.info("Model initialized successfully.")
            else:
                logging.error("Model provider failed to initialize properly.")
        except Exception as e:
            logging.error(f"Error initializing model: {e}")

    # Kick off in threadpool to not block lifespan/startup
    loop = asyncio.get_running_loop()
    loop.run_in_executor(None, load_model)

    yield
    # No specific shutdown actions required

app = FastAPI(title="CiperScope ML Classification Service", version="1.0.0", lifespan=lifespan)

# Security configuration
INTERNAL_AUTH_TOKEN = os.getenv("ML_SERVICE_TOKEN")

# --- Schemas ---

class EmailPayload(BaseModel):
    subject: str
    sender: str
    replyTo: str
    body: str

class PredictionRequest(BaseModel):
    requestId: str
    emailId: str
    organizationId: str
    payload: EmailPayload
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
    if INTERNAL_AUTH_TOKEN is None:
        raise HTTPException(status_code=500, detail="Server misconfiguration: ML_SERVICE_TOKEN is not set")
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

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

class DistilBertModelProvider(ModelProvider):
    def __init__(self):
        self.model_name = "spotproject/spot-distilbert-phishing"
        self.revision = "fc409441b8bfe0bada834c464ee1b88f162a534d"
        self.is_ready = False

        self.label_mapping = {
            0: "LEGITIMATE",
            1: "PHISHING_OR_SPAM"
        }

        if not TRANSFORMERS_AVAILABLE:
            logging.error("Transformers or torch is not installed.")
            return

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                revision=self.revision,
                trust_remote_code=False
            )
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name,
                revision=self.revision,
                use_safetensors=True,
                trust_remote_code=False
            )

            # Validation
            if self.model.config.architectures and "DistilBertForSequenceClassification" not in self.model.config.architectures:
                raise ValueError(f"Expected DistilBertForSequenceClassification, got {self.model.config.architectures}")

            if self.model.config.num_labels != 2:
                raise ValueError(f"Expected exactly 2 labels, got {self.model.config.num_labels}")

            self.model.eval()
            self.is_ready = True

        except Exception as e:
            logging.error(f"Failed to load DistilBertModelProvider: {e}")
            self.is_ready = False

    def predict(self, text: str) -> dict:
        if not self.is_ready:
            return {
                "status": "NOT_AVAILABLE",
                "predictedLabel": None,
                "modelScore": None,
            }

        try:
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
            with torch.no_grad():
                outputs = self.model(**inputs)

            logits = outputs.logits
            if logits.shape[-1] != 2:
                raise ValueError(f"Unexpected logits shape: {logits.shape}")

            probs = torch.softmax(logits, dim=-1)[0]

            score = float(probs[1].item())
            if not (0.0 <= score <= 1.0):
                raise ValueError(f"Score out of bounds: {score}")

            predicted_class = int(probs.argmax(dim=-1).item())
            predicted_label = self.label_mapping.get(predicted_class, "UNKNOWN")

            return {
                "status": "MODEL_PREDICTION",
                "predictedLabel": predicted_label,
                "modelScore": score,
            }
        except Exception as e:
            logging.error(f"Prediction failed: {e}")
            return {
                "status": "FAILED",
                "predictedLabel": None,
                "modelScore": None,
            }

    def get_metadata(self) -> dict:
        if not self.is_ready:
            return {
                "modelName": None,
                "modelVersion": None,
                "artifactSha256": None,
                "tokenizerVersion": None,
                "preprocessingVersion": "1.0",
            }

        return {
            "modelName": self.model_name,
            "modelVersion": self.revision,
            "artifactSha256": self.revision,
            "tokenizerVersion": getattr(self.tokenizer, "name_or_path", self.model_name),
            "preprocessingVersion": "1.0",
        }

# --- Endpoints ---

@app.get("/health")
async def health_check():
    provider_metadata = current_provider.get_metadata()
    model_ready = provider_metadata.get("modelName") is not None

    return {
        "service": "healthy",
        "model": "ready" if model_ready else "not_available"
    }

import unicodedata

@app.post("/api/v1/predict", response_model=PredictionResponse)
async def predict_email(request: PredictionRequest, token: str = Depends(verify_internal_token)):
    # 1. Deterministic Preprocessing
    # Construct the payload
    raw_text = f"[SUBJECT] {request.payload.subject} [FROM] {request.payload.sender} [REPLY-TO] {request.payload.replyTo} [BODY] {request.payload.body}"

    # NFKC normalization and strip
    processed_text = unicodedata.normalize('NFKC', raw_text).strip()

    if len(processed_text) > 100000:
        # Truncate rather than fail, or fail if desired. We will truncate to prevent denial of service.
        processed_text = processed_text[:100000]

    # 2. Inference
    prediction_result = await run_in_threadpool(current_provider.predict, processed_text)
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
