import json
import re
import sys
import argparse
from typing import Dict, Any, List

SECRET_PATTERNS = [
    r"(?i)bearer\s+[a-z0-9\-\._~+/]+=*",
    r"(?i)api_?key\s*[:=]\s*[\"']?[a-z0-9\-]+[\"']?",
    r"(?i)password\s*[:=]\s*[\"']?[^\s\"']+[\"']?",
    r"(?i)secret\s*[:=]\s*[\"']?[^\s\"']+[\"']?",
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
]

def check_secrets(text: str) -> bool:
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, text):
            return True
    return False

def validate_metadata(meta: Dict[str, Any]) -> bool:
    required_keys = [
        "dataset_name", "source", "acquisition_date", "coverage_period",
        "license_terms", "label_methodology", "sanitization_status",
        "deduplication_status", "authorization_status", "known_limitations",
        "intended_purpose", "authorized_for_ml_evaluation",
        "privacy_review_status", "data_owner", "provenance_verified"
    ]

    for key in required_keys:
        if key not in meta:
            print(f"Error: Metadata missing required key: {key}")
            return False

    if meta.get("authorized_for_ml_evaluation") is not True:
        print("Error: Dataset is not authorized for ML evaluation.")
        return False

    if meta.get("privacy_review_status") != "APPROVED":
        print("Error: Privacy review status is not APPROVED.")
        return False

    if meta.get("provenance_verified") is not True:
        print("Error: Provenance is not verified.")
        return False

    valid_purposes = ["ENGINEERING_REGRESSION", "THRESHOLD_CALIBRATION", "FINAL_VALIDATION"]
    if meta.get("intended_purpose") not in valid_purposes:
        print(f"Error: Invalid intended purpose. Must be one of: {valid_purposes}")
        return False

    print("Metadata validation passed.")
    return True

def validate_data(records: List[Dict[str, Any]]) -> bool:
    if not isinstance(records, list):
        print("Error: Data must be a JSON array of records.")
        return False

    required_fields = ["id", "label", "subject", "sender", "replyTo", "body"]
    valid_labels = ["LEGITIMATE", "PHISHING_OR_SPAM"]

    seen_ids = set()
    seen_bodies = set()

    for idx, r in enumerate(records):
        for field in required_fields:
            if field not in r:
                print(f"Error in record index {idx}: Missing required field '{field}'.")
                return False
            if not isinstance(r[field], str):
                print(f"Error in record index {idx}: Field '{field}' must be a string.")
                return False

        if not r["id"].strip():
            print(f"Error in record index {idx}: ID cannot be empty.")
            return False

        if r["id"] in seen_ids:
            print(f"Error: Duplicate ID found: {r['id']}")
            return False
        seen_ids.add(r["id"])

        if r["label"] not in valid_labels:
            print(f"Error for ID {r['id']}: Invalid label '{r['label']}'. Must be one of {valid_labels}.")
            return False

        if r["body"] in seen_bodies:
            print(f"Error: Exact duplicate body detected for ID {r['id']}.")
            return False
        seen_bodies.add(r["body"])

        raw_text = f"[SUBJECT] {r['subject']} [FROM] {r['sender']} [REPLY-TO] {r['replyTo']} [BODY] {r['body']}"
        if check_secrets(raw_text):
            print(f"Error: Potential secret found in ID {r['id']}.")
            print("Automated secret scanning is a safety check, not proof of complete sanitization.")
            return False

    print("Data validation passed.")
    return True

def main():
    parser = argparse.ArgumentParser(description="Validate evaluation dataset and metadata.")
    parser.add_argument("--data", type=str, required=True, help="Path to data JSON")
    parser.add_argument("--metadata", type=str, required=False, help="Path to metadata JSON")

    args = parser.parse_args()

    success = True
    if args.metadata:
        with open(args.metadata, 'r', encoding='utf-8') as f:
            try:
                meta = json.load(f)
                success = success and validate_metadata(meta)
            except json.JSONDecodeError:
                print(f"Error: Invalid JSON in {args.metadata}")
                success = False

    with open(args.data, 'r', encoding='utf-8') as f:
        try:
            records = json.load(f)
            success = success and validate_data(records)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in {args.data}")
            success = False

    if not success:
        sys.exit(1)
    print("Validation successful.")

if __name__ == "__main__":
    main()
