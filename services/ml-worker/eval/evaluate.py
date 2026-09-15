import json
import os
import unicodedata
import argparse
import hashlib
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from validate_dataset import compute_fingerprint

def calc_metrics(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "fpr": fpr, "fnr": fnr
    }

def calculate_pr_auc(y_true, y_scores):
    # Sort by scores descending
    desc_score_indices = sorted(range(len(y_scores)), key=lambda i: y_scores[i], reverse=True)
    y_true_sorted = [y_true[i] for i in desc_score_indices]

    tp, fp = 0, 0
    precision_list = [1.0] # start at 1.0
    recall_list = [0.0]    # start at 0.0
    total_positives = sum(y_true)

    if total_positives == 0:
        return 0.0

    for label in y_true_sorted:
        if label == 1:
            tp += 1
        else:
            fp += 1
        precision_list.append(tp / (tp + fp))
        recall_list.append(tp / total_positives)

    # Calculate AUC using trapezoidal rule
    auc = 0.0
    for i in range(1, len(precision_list)):
        auc += (recall_list[i] - recall_list[i-1]) * (precision_list[i] + precision_list[i-1]) / 2
    return auc

def run_evaluation():
    parser = argparse.ArgumentParser(description="Offline Evaluation & Calibration")
    parser.add_argument("--data", type=str, default=os.path.join(os.path.dirname(__file__), 'data', 'samples.json'), help="Path to evaluation dataset")
    parser.add_argument("--fp-cost", type=float, default=None, help="Explicit False Positive business cost")
    parser.add_argument("--fn-cost", type=float, default=None, help="Explicit False Negative business cost")
    args = parser.parse_args()

    data_path = args.data
    if not os.path.exists(data_path):
        print(f"Error: {data_path} not found.")
        return

    with open(data_path, 'r', encoding='utf-8') as f:
        samples = json.load(f)

    # 1. Dataset Identity & Prevalence Reporting
    total_samples = len(samples)
    print(f"\n--- DATASET IDENTITY ---")
    print(f"File: {data_path}")
    print(f"Dataset Size: {total_samples}")

    # Try to load metadata if present alongside the file
    meta_path = data_path.replace('.json', '_meta.json')
    purpose = "UNKNOWN"
    if os.path.exists(meta_path):
        with open(meta_path, 'r', encoding='utf-8') as mf:
            meta = json.load(mf)
            purpose = meta.get("intended_purpose", "UNKNOWN")

    print(f"Intended Purpose: {purpose}")

    if purpose == "ENGINEERING_REGRESSION":
        print("WARNING: This is an engineering regression set, NOT calibration evidence.")
    elif purpose not in ["THRESHOLD_CALIBRATION", "FINAL_VALIDATION"]:
        print("WARNING: Dataset lacks explicit authorization metadata. Results cannot be used as calibration/final-validation evidence.")

    fingerprint = compute_fingerprint(samples)
    print(f"Canonical Fingerprint (SHA-256): {fingerprint}")

    if total_samples == 0:
        print("Dataset is empty.")
        return

    pos_count = sum(1 for s in samples if s["label"] == "PHISHING_OR_SPAM")
    neg_count = sum(1 for s in samples if s["label"] == "LEGITIMATE")
    pos_prev = pos_count / total_samples
    neg_prev = neg_count / total_samples

    print(f"\n--- LABEL DISTRIBUTION ---")
    print(f"Total: {total_samples}")
    print(f"Positive (PHISHING_OR_SPAM): {pos_count} ({pos_prev:.4f})")
    print(f"Negative (LEGITIMATE):       {neg_count} ({neg_prev:.4f})")

    model_id = "spotproject/spot-distilbert-phishing"
    revision = "fc409441b8bfe0bada834c464ee1b88f162a534d"

    print("\nLoading model... (This may fail if the model is not cached locally)")
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_id, revision=revision, trust_remote_code=False)
        model = AutoModelForSequenceClassification.from_pretrained(
            model_id,
            revision=revision,
            use_safetensors=True,
            trust_remote_code=False
        )
    except Exception as e:
        print("Model loading failed! Evaluator execution blocked by missing model artifact.")
        print(f"Error details: {e}")
        return

    if model.config.architectures != ["DistilBertForSequenceClassification"]:
        print(f"Error: Invalid architecture: {model.config.architectures}")
        return
    if model.config.num_labels != 2:
        print(f"Error: Invalid num_labels: {model.config.num_labels}")
        return

    model.eval()

    y_true = []
    y_scores = []
    results = []

    print("\nRunning inference...")
    for s in samples:
        raw_text = f"[SUBJECT] {s['subject']} [FROM] {s['sender']} [REPLY-TO] {s['replyTo']} [BODY] {s['body']}"
        processed_text = unicodedata.normalize('NFKC', raw_text).strip()[:100000]

        inputs = tokenizer(processed_text, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)[0]
        score = float(probs[1].item())

        actual_binary = 1 if s['label'] == 'PHISHING_OR_SPAM' else 0
        y_true.append(actual_binary)
        y_scores.append(score)

        results.append({
            "id": s["id"],
            "expected": s["label"],
            "score": score
        })

    # Overall Metrics (at generic 0.5 threshold for PR-AUC base)
    pr_auc = calculate_pr_auc(y_true, y_scores)
    print(f"\n--- OVERALL METRICS ---")
    print(f"Model ID: {model_id}")
    print(f"Revision: {revision}")
    print(f"PR-AUC: {pr_auc:.4f}")

    # Threshold analysis
    print(f"\n--- THRESHOLD ANALYSIS ---")
    if args.fp_cost is not None and args.fn_cost is not None:
        print(f"BUSINESS COST OPTIMIZATION: AVAILABLE (FP Cost: {args.fp_cost}, FN Cost: {args.fn_cost})")
        cost_header = " | Cost"
    else:
        print("BUSINESS COST OPTIMIZATION: UNAVAILABLE (Costs not supplied)")
        cost_header = ""

    print(f"{'Threshold':<13} | {'Type':<19} | {'TP':<4} | {'FP':<4} | {'TN':<4} | {'FN':<4} | {'Prec':<6} | {'Rec':<6} | {'F1':<6} | {'FPR':<6} | {'FNR':<6}{cost_header}")
    print("-" * (108 + len(cost_header)))

    thresholds_to_test = [i/100.0 for i in range(101)]
    best_f1 = -1
    best_f1_t = 0

    threshold_metrics = {}
    for t in thresholds_to_test:
        y_pred = [1 if s > t else 0 for s in y_scores]
        m = calc_metrics(y_true, y_pred)
        threshold_metrics[t] = m
        if m['f1'] > best_f1:
            best_f1 = m['f1']
            best_f1_t = t

    for t in thresholds_to_test:
        m = threshold_metrics[t]
        t_type = "CANDIDATE THRESHOLD"
        if t in [0.40, 0.85]:
            t_type = "PRODUCTION REFERENCE"
        elif t == best_f1_t:
            t_type = "METRIC-OPTIMAL (F1)"

        cost_str = ""
        if args.fp_cost is not None and args.fn_cost is not None:
            total_cost = (m['fp'] * args.fp_cost) + (m['fn'] * args.fn_cost)
            cost_str = f" | {total_cost:<.2f}"

        # We only print interesting thresholds to save space unless it's a prod or optimal threshold, or every 0.1
        if t in [0.40, 0.85] or t == best_f1_t or int(t*100) % 10 == 0:
            print(f"{t:<13.2f} | {t_type:<19} | {m['tp']:<4} | {m['fp']:<4} | {m['tn']:<4} | {m['fn']:<4} | {m['precision']:<6.4f} | {m['recall']:<6.4f} | {m['f1']:<6.4f} | {m['fpr']:<6.4f} | {m['fnr']:<6.4f}{cost_str}")

    # Production Confusion Matrices
    print("\n--- CONFUSION MATRICES AT PROD THRESHOLDS ---")
    for t in [0.40, 0.85]:
        m = threshold_metrics[t]
        print(f"PRODUCTION REFERENCE THRESHOLD: {t}")
        print(f"TP: {m['tp']}, FP: {m['fp']}, TN: {m['tn']}, FN: {m['fn']}\n")

if __name__ == "__main__":
    run_evaluation()
