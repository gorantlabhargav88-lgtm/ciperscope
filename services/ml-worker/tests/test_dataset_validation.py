import unittest
import sys
import os
from typing import Dict, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'eval'))
from validate_dataset import validate_metadata, validate_data, compute_fingerprint, validate_separation

class TestDatasetValidation(unittest.TestCase):
    def get_valid_metadata(self) -> Dict[str, Any]:
        return {
            "dataset_name": "Test Dataset",
            "source": "Internal",
            "acquisition_date": "2026-09-15",
            "coverage_period": "Q3",
            "license_terms": "Internal Only",
            "label_methodology": "Manual",
            "sanitization_status": "Sanitized",
            "deduplication_status": "Deduplicated",
            "authorization_status": "Authorized",
            "known_limitations": "None",
            "intended_purpose": "THRESHOLD_CALIBRATION",
            "authorized_for_ml_evaluation": True,
            "privacy_review_status": "APPROVED",
            "data_owner": "Security Team",
            "provenance_verified": True
        }

    def get_valid_record(self) -> Dict[str, Any]:
        return {
            "id": "1",
            "label": "LEGITIMATE",
            "subject": "Test",
            "sender": "test@example.com",
            "replyTo": "test@example.com",
            "body": "Hello world"
        }

    # METADATA TESTS
    def test_valid_metadata(self):
        self.assertTrue(validate_metadata(self.get_valid_metadata()))

    def test_missing_field_metadata(self):
        meta = self.get_valid_metadata()
        del meta["dataset_name"]
        self.assertFalse(validate_metadata(meta))

    def test_missing_authorization(self):
        meta = self.get_valid_metadata()
        meta["authorized_for_ml_evaluation"] = False
        self.assertFalse(validate_metadata(meta))

    def test_unauthorized_dataset(self):
        meta = self.get_valid_metadata()
        meta["privacy_review_status"] = "PENDING"
        self.assertFalse(validate_metadata(meta))

    def test_invalid_purpose(self):
        meta = self.get_valid_metadata()
        meta["intended_purpose"] = "UNKNOWN"
        self.assertFalse(validate_metadata(meta))

    def test_missing_provenance(self):
        meta = self.get_valid_metadata()
        meta["provenance_verified"] = False
        self.assertFalse(validate_metadata(meta))

    # DATA TESTS
    def test_valid_schema(self):
        self.assertTrue(validate_data([self.get_valid_record()]))

    def test_missing_field(self):
        r = self.get_valid_record()
        del r["subject"]
        self.assertFalse(validate_data([r]))

    def test_invalid_type(self):
        r = self.get_valid_record()
        r["subject"] = 123
        self.assertFalse(validate_data([r]))

    def test_invalid_label(self):
        r = self.get_valid_record()
        r["label"] = "SPAM"
        self.assertFalse(validate_data([r]))

    def test_duplicate_id(self):
        r1 = self.get_valid_record()
        r2 = self.get_valid_record()
        r2["body"] = "Different"
        self.assertFalse(validate_data([r1, r2]))

    def test_duplicate_record_body(self):
        r1 = self.get_valid_record()
        r2 = self.get_valid_record()
        r2["id"] = "2"
        self.assertFalse(validate_data([r1, r2]))

    def test_secret_like_content_detection(self):
        r = self.get_valid_record()
        r["body"] = "Here is my password: 'password123'"
        self.assertFalse(validate_data([r]))

    # SEPARATION TESTS
    def test_deterministic_fingerprint(self):
        r1 = self.get_valid_record()
        r2 = self.get_valid_record()
        r2["id"] = "2"
        f1 = compute_fingerprint([r1, r2])
        f2 = compute_fingerprint([r1, r2])
        self.assertEqual(f1, f2)

    def test_canonicalization_formatting_independence(self):
        r1 = self.get_valid_record()
        # The fingerprint function extracts fields and re-serializes,
        # so adding an extra ignored field or changing key order in the dict shouldn't matter.
        r1_mod = self.get_valid_record()
        r1_mod["extra"] = "ignored"
        self.assertEqual(compute_fingerprint([r1]), compute_fingerprint([r1_mod]))

    def test_record_order_behavior(self):
        r1 = self.get_valid_record()
        r2 = self.get_valid_record()
        r2["id"] = "2"
        self.assertNotEqual(compute_fingerprint([r1, r2]), compute_fingerprint([r2, r1]))

    def test_different_datasets_different_fingerprints(self):
        r1 = self.get_valid_record()
        r2 = self.get_valid_record()
        r2["id"] = "2"
        self.assertNotEqual(compute_fingerprint([r1]), compute_fingerprint([r2]))

    def test_identical_calibration_final_rejected(self):
        cal_meta = self.get_valid_metadata()
        cal_meta["intended_purpose"] = "THRESHOLD_CALIBRATION"
        val_meta = self.get_valid_metadata()
        val_meta["intended_purpose"] = "FINAL_VALIDATION"

        cal_data = [self.get_valid_record()]
        val_data = [self.get_valid_record()]

        self.assertFalse(validate_separation(cal_data, cal_meta, val_data, val_meta))

    def test_overlapping_record_ids_rejected(self):
        cal_meta = self.get_valid_metadata()
        cal_meta["intended_purpose"] = "THRESHOLD_CALIBRATION"
        val_meta = self.get_valid_metadata()
        val_meta["intended_purpose"] = "FINAL_VALIDATION"

        cal_data = [self.get_valid_record()]
        val_data = [self.get_valid_record()]
        val_data[0]["body"] = "Different body to pass fingerprint test but ID overlaps"

        self.assertFalse(validate_separation(cal_data, cal_meta, val_data, val_meta))

    def test_disjoint_calibration_final_accepted(self):
        cal_meta = self.get_valid_metadata()
        cal_meta["intended_purpose"] = "THRESHOLD_CALIBRATION"
        val_meta = self.get_valid_metadata()
        val_meta["intended_purpose"] = "FINAL_VALIDATION"

        cal_data = [self.get_valid_record()]
        val_data = [self.get_valid_record()]
        val_data[0]["id"] = "2"
        val_data[0]["body"] = "Completely different"

        self.assertTrue(validate_separation(cal_data, cal_meta, val_data, val_meta))

    def test_engineering_regression_rejected(self):
        cal_meta = self.get_valid_metadata()
        cal_meta["intended_purpose"] = "ENGINEERING_REGRESSION"
        val_meta = self.get_valid_metadata()
        val_meta["intended_purpose"] = "FINAL_VALIDATION"

        cal_data = [self.get_valid_record()]
        val_data = [self.get_valid_record()]
        val_data[0]["id"] = "2"

        self.assertFalse(validate_separation(cal_data, cal_meta, val_data, val_meta))

if __name__ == '__main__':
    unittest.main()
