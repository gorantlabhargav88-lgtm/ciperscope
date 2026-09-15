import pytest
from fastapi.testclient import TestClient
from app.main import app, INTERNAL_AUTH_TOKEN, DistilBertModelProvider, ModelProvider
import time
from unittest.mock import patch, MagicMock
import torch

# TestClient is created locally to trigger lifespan

valid_payload = {
    "requestId": "req-1",
    "emailId": "email-1",
    "organizationId": "org-1",
    "payload": {
        "subject": "test",
        "sender": "a@b.com",
        "replyTo": "c@d.com",
        "body": "hello"
    },
    "preprocessingVersion": "1.0",
    "requestedModelVersion": "latest"
}

def get_headers(token=INTERNAL_AUTH_TOKEN):
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def mock_transformers():
    with patch("app.main.AutoTokenizer.from_pretrained") as mock_tokenizer, \
         patch("app.main.AutoModelForSequenceClassification.from_pretrained") as mock_model:

        # Setup mock tokenizer
        tokenizer_instance = MagicMock()
        tokenizer_instance.return_value = {"input_ids": torch.tensor([[1, 2, 3]])}
        mock_tokenizer.return_value = tokenizer_instance

        # Setup mock model
        model_instance = MagicMock()
        model_instance.config.architectures = ["DistilBertForSequenceClassification"]
        model_instance.config.num_labels = 2

        # Mock forward pass returning logits
        class MockOutput:
            def __init__(self, logits):
                self.logits = logits
        model_instance.return_value = MockOutput(torch.tensor([[-1.0, 1.0]]))

        mock_model.return_value = model_instance
        yield mock_tokenizer, mock_model

def test_health_service_startup():
    with patch("app.main.current_provider", MagicMock(get_metadata=lambda: {"modelName": None})):
        with TestClient(app) as client:
            response = client.get("/health")
            assert response.status_code == 200
            assert response.json() == {"service": "healthy", "model": "not_available"}

def test_module_import_does_not_block():
    import app.main
    assert isinstance(app.main.current_provider, app.main.UnavailableModelProvider) or app.main.current_provider is None

def test_prediction_contract_validation(mock_transformers):
    # Test with DistilBertModelProvider
    provider = DistilBertModelProvider()
    assert provider.is_ready is True

    with patch("app.main.current_provider", provider):
        with TestClient(app) as client:
            response = client.post("/api/v1/predict", json=valid_payload, headers=get_headers())
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "MODEL_PREDICTION"
        assert data["predictedLabel"] == "PHISHING_OR_SPAM"
        assert data["modelScore"] is not None
        assert 0.0 <= data["modelScore"] <= 1.0

        # 19. no BEC prediction fabrication
        assert data["predictedLabel"] != "BEC"

def test_model_initialization_args(mock_transformers):
    mock_tokenizer, mock_model = mock_transformers
    provider = DistilBertModelProvider()

    # 2. exact revision configuration
    # 3. safetensors enforcement
    # 4. trust_remote_code=False
    mock_tokenizer.assert_called_with(
        "spotproject/spot-distilbert-phishing",
        revision="fc409441b8bfe0bada834c464ee1b88f162a534d",
        trust_remote_code=False
    )
    mock_model.assert_called_with(
        "spotproject/spot-distilbert-phishing",
        revision="fc409441b8bfe0bada834c464ee1b88f162a534d",
        use_safetensors=True,
        trust_remote_code=False
    )

def test_expected_architecture(mock_transformers):
    # 5. expected architecture
    mock_tokenizer, mock_model = mock_transformers
    mock_model.return_value.config.architectures = ["WrongArchitecture"]

    provider = DistilBertModelProvider()
    assert provider.is_ready is False

def test_expected_num_labels(mock_transformers):
    # 6. two output logits
    mock_tokenizer, mock_model = mock_transformers
    mock_model.return_value.config.num_labels = 3

    provider = DistilBertModelProvider()
    assert provider.is_ready is False

def test_prediction_logic(mock_transformers):
    # 7. deterministic label mapping
    # 8. softmax probability calculation
    # 9. modelScore == probability[1]
    mock_tokenizer, mock_model = mock_transformers
    provider = DistilBertModelProvider()

    # Logits [-1.0, 1.0] -> softmax is roughly [0.1192, 0.8808]
    result = provider.predict("test")
    assert result["status"] == "MODEL_PREDICTION"
    assert result["predictedLabel"] == "PHISHING_OR_SPAM"
    assert 0.88 < result["modelScore"] < 0.89

    # Test class 0
    class MockOutput:
        def __init__(self, logits):
            self.logits = logits
    mock_model.return_value.return_value = MockOutput(torch.tensor([[2.0, -1.0]]))

    result2 = provider.predict("test")
    assert result2["predictedLabel"] == "LEGITIMATE"
    assert result2["modelScore"] < 0.1

def test_unexpected_output_dimension(mock_transformers):
    # 15. unexpected output dimension
    mock_tokenizer, mock_model = mock_transformers
    provider = DistilBertModelProvider()

    class MockOutput:
        def __init__(self, logits):
            self.logits = logits
    mock_model.return_value.return_value = MockOutput(torch.tensor([[1.0, 2.0, 3.0]]))

    result = provider.predict("test")
    assert result["status"] == "FAILED"
    assert result["modelScore"] is None

def test_long_input_truncation(mock_transformers):
    # 13. long input/token truncation
    mock_tokenizer, mock_model = mock_transformers
    provider = DistilBertModelProvider()

    result = provider.predict("A" * 100001)
    # The tokenizer mock is called with the truncated string
    mock_tokenizer.return_value.assert_called_with("A" * 100001, return_tensors="pt", truncation=True, max_length=512)

def test_model_loading_failure(mock_transformers):
    # 16. model-loading failure
    mock_tokenizer, mock_model = mock_transformers
    mock_model.side_effect = Exception("Download failed")

    provider = DistilBertModelProvider()
    assert provider.is_ready is False

    # 18. NOT_AVAILABLE degradation
    result = provider.predict("test")
    assert result["status"] == "NOT_AVAILABLE"

def test_prediction_failure(mock_transformers):
    # 17. prediction failure
    mock_tokenizer, mock_model = mock_transformers
    provider = DistilBertModelProvider()

    mock_model.return_value.side_effect = Exception("Runtime error")
    result = provider.predict("test")
    assert result["status"] == "FAILED"

def test_malformed_request():
    bad_payload = {
        "requestId": "req-1",
        "organizationId": "org-1",
        "payload": {
            "subject": "test"
        },
        "preprocessingVersion": "1.0",
        "requestedModelVersion": "latest"
    }
    with TestClient(app) as client:
        response = client.post("/api/v1/predict", json=bad_payload, headers=get_headers())
    assert response.status_code == 422
