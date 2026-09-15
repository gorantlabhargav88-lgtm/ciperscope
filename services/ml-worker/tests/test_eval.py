import json
import os
import unittest

class TestEvalDataset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data_path = os.path.join(os.path.dirname(__file__), '..', 'eval', 'data', 'samples.json')
        with open(data_path, 'r', encoding='utf-8') as f:
            cls.samples = json.load(f)

    def test_dataset_size_and_type(self):
        self.assertIsInstance(self.samples, list)
        self.assertGreater(len(self.samples), 0, "Dataset should not be empty")

    def test_schema_fields(self):
        required_fields = {"id", "label", "subject", "sender", "replyTo", "body"}
        for s in self.samples:
            self.assertTrue(required_fields.issubset(s.keys()), f"Missing fields in sample {s.get('id')}")

    def test_unique_ids(self):
        ids = [s["id"] for s in self.samples]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate IDs found in dataset")

    def test_valid_labels(self):
        valid_labels = {"LEGITIMATE", "PHISHING_OR_SPAM"}
        for s in self.samples:
            self.assertIn(s["label"], valid_labels, f"Invalid label {s['label']} in {s['id']}")

if __name__ == '__main__':
    unittest.main()
