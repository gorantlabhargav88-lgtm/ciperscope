import json
import re
import sys
import argparse
import hashlib
from typing import Dict, Any, List
from datetime import datetime

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

def validate_timestamp(ts: Any) -> bool:
    if not isinstance(ts, str):
        return False
    if not re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$', ts):
        return False
    try:
        if '.' in ts:
            datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False

def validate_hash(h: Any) -> bool:
    if not isinstance(h, str):
        return False
    return bool(re.match(r'^[a-f0-9]{64}$', h))

def validate_metadata(meta: Dict[str, Any]) -> bool:
    required_keys = [
        "dataset_name", "source", "acquisition_date", "coverage_period",
        "license_terms", "label_methodology", "sanitization_status",
        "deduplication_status", "authorization_status", "known_limitations",
        "intended_purpose", "authorized_for_ml_evaluation",
        "privacy_review_status", "data_owner", "provenance_verified",
        "labeling_method"
    ]

    for key in required_keys:
        if key not in meta:
            print(f"Error: Metadata missing required key: {key}")
            return False

    if not isinstance(meta.get("labeling_method"), str) or not meta.get("labeling_method").strip():
        print("Error: labeling_method must be a non-empty string.")
        return False

    if "labeling_evidence_id" in meta:
        if not isinstance(meta.get("labeling_evidence_id"), str):
            print("Error: labeling_evidence_id must be a string.")
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

    purpose = meta.get("intended_purpose")
    if purpose in ["THRESHOLD_CALIBRATION", "FINAL_VALIDATION"]:
        if "authorization_evidence_id" not in meta:
            print(f"Error: authorization_evidence_id is required for purpose {purpose}.")
            return False
        if not isinstance(meta["authorization_evidence_id"], str) or not meta["authorization_evidence_id"].strip():
            print("Error: authorization_evidence_id must be a non-empty string.")
            return False

        if "semantic_candidate_review_status" not in meta:
            print(f"Error: semantic_candidate_review_status is required for purpose {purpose}.")
            return False

    valid_semantic_statuses = ["NOT_REVIEWED", "REVIEWED_NO_LEAKAGE", "REVIEWED_POTENTIAL_LEAKAGE"]
    if "semantic_candidate_review_status" in meta:
        if meta["semantic_candidate_review_status"] not in valid_semantic_statuses:
            print(f"Error: Invalid semantic_candidate_review_status. Must be one of: {valid_semantic_statuses}")
            return False

    if "authorization_evidence_id" in meta:
        if not isinstance(meta["authorization_evidence_id"], str) or not meta["authorization_evidence_id"].strip():
            print("Error: authorization_evidence_id must be a non-empty string.")
            return False

    print("Metadata validation passed.")
    return True

def validate_data(records: List[Dict[str, Any]], meta: Dict[str, Any] = None) -> bool:
    if not isinstance(records, list):
        print("Error: Data must be a JSON array of records.")
        return False

    required_fields = ["id", "label", "subject", "sender", "replyTo", "body"]
    valid_labels = ["LEGITIMATE", "PHISHING_OR_SPAM"]

    requires_leakage_meta = False
    if meta and meta.get("intended_purpose") in ["THRESHOLD_CALIBRATION", "FINAL_VALIDATION"]:
        requires_leakage_meta = True

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

        if requires_leakage_meta:
            for field in ["timestamp", "campaign_hash", "sender_domain_hash"]:
                if field not in r:
                    print(f"Error in record index {idx}: Missing required leakage field '{field}' for purpose {meta.get('intended_purpose')}.")
                    return False

        if "timestamp" in r:
            if not validate_timestamp(r["timestamp"]):
                print(f"Error in record index {idx}: Invalid timestamp '{r['timestamp']}'. Must be ISO-8601 UTC (YYYY-MM-DDTHH:MM:SSZ).")
                return False

        for hash_field in ["campaign_hash", "sender_domain_hash", "url_domain_hash"]:
            if hash_field in r:
                if not validate_hash(r[hash_field]):
                    print(f"Error in record index {idx}: Invalid {hash_field} '{r[hash_field]}'. Must be a 64-character lowercase hex string.")
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

def compute_fingerprint(records: List[Dict[str, Any]]) -> str:
    """
    Computes a deterministic SHA-256 fingerprint of the dataset.
    Canonicalization rule:
    1. Extract strictly required fields (id, label, subject, sender, replyTo, body).
    2. Maintain the exact record ordering provided in the list.
    3. Serialize to JSON using sorted keys and compact separators without whitespace.
    """
    canonical_records = []
    for r in records:
        canonical_records.append({
            "id": r["id"],
            "label": r["label"],
            "subject": r["subject"],
            "sender": r["sender"],
            "replyTo": r["replyTo"],
            "body": r["body"]
        })
    canonical_json = json.dumps(canonical_records, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()

def validate_separation(cal_records: List[Dict[str, Any]], cal_meta: Dict[str, Any], val_records: List[Dict[str, Any]], val_meta: Dict[str, Any]) -> bool:
    if cal_meta.get("intended_purpose") != "THRESHOLD_CALIBRATION":
        print("Error: Calibration dataset intended_purpose must be THRESHOLD_CALIBRATION.")
        return False

    if val_meta.get("intended_purpose") != "FINAL_VALIDATION":
        print("Error: Validation dataset intended_purpose must be FINAL_VALIDATION.")
        return False

    cal_fingerprint = compute_fingerprint(cal_records)
    val_fingerprint = compute_fingerprint(val_records)

    if cal_fingerprint == val_fingerprint:
        print("Error: Calibration and Validation datasets have identical fingerprints.")
        return False

    cal_ids = {r["id"] for r in cal_records}
    val_ids = {r["id"] for r in val_records}

    overlap = cal_ids.intersection(val_ids)
    if overlap:
        print(f"Error: Datasets overlap with {len(overlap)} identical record IDs.")
        return False

    cal_campaigns = {r["campaign_hash"] for r in cal_records if "campaign_hash" in r}
    val_campaigns = {r["campaign_hash"] for r in val_records if "campaign_hash" in r}
    if cal_campaigns.intersection(val_campaigns):
        print("Error: Calibration and Validation datasets have overlapping campaign_hash.")
        return False

    cal_senders = {r["sender_domain_hash"] for r in cal_records if "sender_domain_hash" in r}
    val_senders = {r["sender_domain_hash"] for r in val_records if "sender_domain_hash" in r}
    if cal_senders.intersection(val_senders):
        print("Error: Calibration and Validation datasets have overlapping sender_domain_hash.")
        return False

    cal_urls = {r["url_domain_hash"] for r in cal_records if "url_domain_hash" in r}
    val_urls = {r["url_domain_hash"] for r in val_records if "url_domain_hash" in r}
    if cal_urls.intersection(val_urls):
        print("Error: Calibration and Validation datasets have overlapping url_domain_hash.")
        return False

    def parse_timestamp(ts: str) -> datetime:
        if '.' in ts:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

    cal_timestamps = [parse_timestamp(r["timestamp"]) for r in cal_records if "timestamp" in r]
    val_timestamps = [parse_timestamp(r["timestamp"]) for r in val_records if "timestamp" in r]

    if cal_timestamps and val_timestamps:
        cal_max = max(cal_timestamps)
        val_min = min(val_timestamps)
        if cal_max >= val_min:
            print("Error: Temporal leakage detected. Calibration max timestamp must be strictly less than validation min timestamp.")
            return False

    print("Separation validation passed.")
    return True

def main():
    parser = argparse.ArgumentParser(description="Validate evaluation dataset and metadata.")
    parser.add_argument("--data", type=str, required=False, help="Path to data JSON")
    parser.add_argument("--metadata", type=str, required=False, help="Path to metadata JSON")

    parser.add_argument("--cal-data", type=str, help="Path to calibration data JSON")
    parser.add_argument("--cal-metadata", type=str, help="Path to calibration metadata JSON")
    parser.add_argument("--val-data", type=str, help="Path to validation data JSON")
    parser.add_argument("--val-metadata", type=str, help="Path to validation metadata JSON")

    args = parser.parse_args()

    success = True

    if args.cal_data and args.val_data and args.cal_metadata and args.val_metadata:
        try:
            with open(args.cal_metadata, 'r', encoding='utf-8') as f:
                cal_meta = json.load(f)
            with open(args.val_metadata, 'r', encoding='utf-8') as f:
                val_meta = json.load(f)
            with open(args.cal_data, 'r', encoding='utf-8') as f:
                cal_records = json.load(f)
            with open(args.val_data, 'r', encoding='utf-8') as f:
                val_records = json.load(f)

            if validate_metadata(cal_meta) and validate_metadata(val_meta) and validate_data(cal_records, cal_meta) and validate_data(val_records, val_meta):
                success = success and validate_separation(cal_records, cal_meta, val_records, val_meta)
            else:
                success = False
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON during separation validation: {e}")
            success = False
    elif args.data:
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
                meta_to_pass = meta if 'meta' in locals() else None
                success = success and validate_data(records, meta_to_pass)
            except json.JSONDecodeError:
                print(f"Error: Invalid JSON in {args.data}")
                success = False
    else:
        print("Error: Provide either --data or all separation args (--cal-data, --cal-metadata, --val-data, --val-metadata).")
        success = False

    if not success:
        sys.exit(1)
    print("Validation successful.")

if __name__ == "__main__":
    main()
