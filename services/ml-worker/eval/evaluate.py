import json
import os
import unicodedata
import argparse
import hashlib
import random
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from validate_dataset import compute_fingerprint
from collections import Counter
from datetime import datetime
import re
def calc_metrics(y_true, y_pred, safe_undefined=False):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

    def safe_div(num, den):
        if den > 0:
            return num / den
        return None if safe_undefined else 0.0

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)

    f1 = None if safe_undefined else 0.0
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * (precision * recall) / (precision + recall)

    fpr = safe_div(fp, fp + tn)
    fnr = safe_div(fn, fn + tp)

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

def compute_score_distribution(scores):
    if not scores:
        return {}
    s = sorted(scores)
    n = len(s)
    mean_val = sum(s) / n
    std_val = (sum((x - mean_val)**2 for x in s) / n) ** 0.5 if n > 1 else 0.0

    def quantile(q):
        idx = (n - 1) * q
        low = int(idx)
        high = min(low + 1, n - 1)
        weight = idx - low
        return s[low] * (1.0 - weight) + s[high] * weight

    return {
        "count": n,
        "min": s[0],
        "max": s[-1],
        "mean": mean_val,
        "median": quantile(0.5),
        "std": std_val,
        "p25": quantile(0.25),
        "p75": quantile(0.75),
        "p90": quantile(0.90),
        "p99": quantile(0.99)
    }

def bootstrap_metrics(y_true, y_pred, n_resamples=1000, seed=42, ci_level=0.95):
    if not y_true:
        return {}
    random.seed(seed)
    n = len(y_true)
    metrics_list = {'precision': [], 'recall': [], 'f1': [], 'fpr': [], 'fnr': []}

    for _ in range(n_resamples):
        indices = [random.randint(0, n - 1) for _ in range(n)]
        y_t = [y_true[i] for i in indices]
        y_p = [y_pred[i] for i in indices]

        m = calc_metrics(y_t, y_p, safe_undefined=True)
        for k in metrics_list:
            if m[k] is not None:
                metrics_list[k].append(m[k])

    ci_results = {}
    lower_p = (1.0 - ci_level) / 2.0
    upper_p = 1.0 - lower_p

    for k, v in metrics_list.items():
        if len(v) < 2:
            ci_results[k] = None
        else:
            sv = sorted(v)
            lower_idx = int((len(v) - 1) * lower_p)
            upper_idx = int((len(v) - 1) * upper_p)
            ci_results[k] = (sv[lower_idx], sv[upper_idx])

    return ci_results

def compute_calibration_metrics(y_true, y_scores, n_bins=10):
    if not y_true:
        return {"brier": 0.0, "ece": 0.0, "reliability": []}

    n = len(y_true)
    brier = sum((s - t)**2 for s, t in zip(y_scores, y_true)) / n

    # ECE and Reliability
    bins = [{"lower": i / n_bins, "upper": (i + 1) / n_bins, "count": 0, "sum_t": 0.0, "sum_s": 0.0} for i in range(n_bins)]

    for s, t in zip(y_scores, y_true):
        bin_idx = int(s * n_bins)
        if bin_idx == n_bins:
            bin_idx = n_bins - 1
        b = bins[bin_idx]
        b["count"] += 1
        b["sum_t"] += t
        b["sum_s"] += s

    ece = 0.0
    reliability = []

    for b in bins:
        if b["count"] > 0:
            empirical_rate = b["sum_t"] / b["count"]
            mean_prob = b["sum_s"] / b["count"]
            weight = b["count"] / n
            ece += weight * abs(empirical_rate - mean_prob)
            reliability.append({
                "lower": b["lower"],
                "upper": b["upper"],
                "count": b["count"],
                "mean_prob": mean_prob,
                "empirical_rate": empirical_rate
            })

    return {"brier": brier, "ece": ece, "reliability": reliability}

def parse_timestamp(ts: str) -> datetime:
    if '.' in ts:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

def compute_hash_concentration(samples, key):
    counts = Counter(s[key] for s in samples if key in s)
    records_with_metadata = sum(counts.values())
    records_without_metadata = len(samples) - records_with_metadata
    unique_groups = len(counts)

    if records_with_metadata == 0:
        return {
            "unique_groups": 0,
            "records_with_metadata": 0,
            "records_without_metadata": records_without_metadata,
            "top_groups": []
        }

    # Sort deterministically: descending count, then ascending hash (to break ties)
    sorted_groups = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    top_3 = sorted_groups[:3]

    top_groups = []
    for rank, (h, c) in enumerate(top_3, 1):
        percentage = (c / records_with_metadata) * 100
        top_groups.append({
            "rank": rank,
            "count": c,
            "percentage": percentage,
            # We explicitly do NOT include the hash here to ensure it's not printed
        })

    return {
        "unique_groups": unique_groups,
        "records_with_metadata": records_with_metadata,
        "records_without_metadata": records_without_metadata,
        "top_groups": top_groups
    }

def print_hash_concentration(stats, title, is_url=False):
    print(f"{title}:")
    print(f"  unique_groups: {stats['unique_groups']}")
    print(f"  records_with_metadata: {stats['records_with_metadata']}")
    if is_url:
        print(f"  records_without_metadata: {stats['records_without_metadata']}")

    if stats['records_with_metadata'] > 0:
        print("  top_groups:")
        for g in stats['top_groups']:
            print(f"    rank={g['rank']} count={g['count']} percentage={g['percentage']:.2f}")

def compute_temporal_distribution(samples):
    timestamps = [parse_timestamp(s["timestamp"]) for s in samples if "timestamp" in s]
    if not timestamps:
        return None

    earliest = min(timestamps)
    latest = max(timestamps)
    span = latest - earliest
    return {
        "earliest": earliest,
        "latest": latest,
        "span": span
    }

def print_temporal_distribution(stats):
    print("Temporal distribution:")
    if not stats:
        print("  metadata: UNAVAILABLE")
        return

    print(f"  earliest: {stats['earliest'].isoformat() + 'Z'}")
    print(f"  latest: {stats['latest'].isoformat() + 'Z'}")
    print(f"  span: {stats['span']}")

def compute_and_print_concentration(samples):
    print(f"\n--- CONCENTRATION STATISTICS ---")
    if not samples:
        print("Dataset is empty.")
        return

    camp_stats = compute_hash_concentration(samples, "campaign_hash")
    print_hash_concentration(camp_stats, "Campaign concentration")

    sender_stats = compute_hash_concentration(samples, "sender_domain_hash")
    print_hash_concentration(sender_stats, "Sender-domain concentration")

    url_stats = compute_hash_concentration(samples, "url_domain_hash")
    print_hash_concentration(url_stats, "URL-domain concentration", is_url=True)

    temp_stats = compute_temporal_distribution(samples)
    print_temporal_distribution(temp_stats)

def normalize_text_to_tokens(text: str) -> set:
    if not text:
        return set()
    text = unicodedata.normalize('NFKC', text)
    # Remove punctuation, lowercase, split on whitespace, returning unique tokens
    text = re.sub(r'[^\w\s]', '', text.lower())
    return set(text.split())

def jaccard_similarity(set1: set, set2: set) -> float:
    # If both sets are empty, return 0.0 to prevent false 100% matches
    if not set1 and not set2:
        return 0.0
    # If one is empty, return 0.0
    if not set1 or not set2:
        return 0.0

    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    return intersection / union

def get_record_tokens(record: dict) -> set:
    subject = record.get("subject", "")
    body = record.get("body", "")
    combined = f"{subject} {body}"
    return normalize_text_to_tokens(combined)

def find_semantic_candidates(calibration_samples: list, validation_samples: list, threshold: float):
    if not (0.0 <= threshold <= 1.0):
        raise ValueError("Threshold must be between 0.0 and 1.0")

    candidates = []

    # Pre-tokenize to avoid repeated work, keeping only set semantics.
    # Token frequency is not represented because we only want a high-level
    # structural lexical overlap (set semantics) rather than term frequency weighting,
    # which avoids issues with repeated spam keywords inflating similarity.
    calib_tokens = [(s["id"], get_record_tokens(s)) for s in calibration_samples]
    valid_tokens = [(s["id"], get_record_tokens(s)) for s in validation_samples]

    for c_id, c_toks in calib_tokens:
        for v_id, v_toks in valid_tokens:
            sim = jaccard_similarity(c_toks, v_toks)
            if sim >= threshold:
                candidates.append({
                    "calibration_id": c_id,
                    "validation_id": v_id,
                    "similarity": sim
                })

    # Deterministic sort: similarity descending, then calib_id asc, valid_id asc
    candidates.sort(key=lambda x: (-x["similarity"], x["calibration_id"], x["validation_id"]))

    return {
        "candidate_count": len(candidates),
        "threshold": threshold,
        "candidates": candidates
    }

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

    compute_and_print_concentration(samples)

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

    # 2. Score Distribution
    dist = compute_score_distribution(y_scores)
    if dist:
        print(f"\n--- SCORE DISTRIBUTION ---")
        print(f"Count: {dist['count']}")
        print(f"Mean: {dist['mean']:.4f} | Median: {dist['median']:.4f} | StdDev: {dist['std']:.4f}")
        print(f"Min: {dist['min']:.4f} | Max: {dist['max']:.4f}")
        print(f"Quantiles -> P25: {dist['p25']:.4f} | P75: {dist['p75']:.4f} | P90: {dist['p90']:.4f} | P99: {dist['p99']:.4f}")

    # 3. Calibration Metrics
    calib = compute_calibration_metrics(y_true, y_scores)
    print(f"\n--- PROBABILITY CALIBRATION METRICS ---")
    print(f"Brier Score: {calib['brier']:.4f}")
    print(f"Expected Calibration Error (ECE): {calib['ece']:.4f}")
    print(f"Reliability Diagram Data (10 bins):")
    for r in calib['reliability']:
        print(f"  Bin [{r['lower']:.1f}-{r['upper']:.1f}): Count={r['count']}, MeanProb={r['mean_prob']:.4f}, EmpRate={r['empirical_rate']:.4f}")
    print("\nNote: Computing Brier score, ECE, or confidence intervals does not by itself calibrate the model or establish a production threshold.")

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

    # Bootstrap Confidence Intervals for Key Thresholds
    print("\n--- BOOTSTRAP UNCERTAINTY (95% CI, 1000 resamples) ---")
    for t in [0.40, 0.85, best_f1_t]:
        if t not in [0.40, 0.85]:
            print(f"\nMETRIC-OPTIMAL THRESHOLD: {t}")
        else:
            print(f"\nPRODUCTION REFERENCE THRESHOLD: {t}")

        y_pred = [1 if s > t else 0 for s in y_scores]
        ci = bootstrap_metrics(y_true, y_pred, n_resamples=1000, seed=42, ci_level=0.95)
        m = threshold_metrics[t]
        if ci:
            for metric_key, label in [('f1', 'F1'), ('precision', 'Precision'), ('recall', 'Recall'), ('fpr', 'FPR'), ('fnr', 'FNR')]:
                if ci[metric_key] is not None:
                    print(f"{label:<10}: {m[metric_key]:.4f} [95% CI: {ci[metric_key][0]:.4f} - {ci[metric_key][1]:.4f}]")
                else:
                    print(f"{label:<10}: {m[metric_key]:.4f} [95% CI: UNAVAILABLE]")
        else:
            print("Confidence Intervals unavailable (empty dataset).")

    # Production Confusion Matrices
    print("\n--- CONFUSION MATRICES AT PROD THRESHOLDS ---")
    for t in [0.40, 0.85]:
        m = threshold_metrics[t]
        print(f"PRODUCTION REFERENCE THRESHOLD: {t}")
        print(f"TP: {m['tp']}, FP: {m['fp']}, TN: {m['tn']}, FN: {m['fn']}\n")

if __name__ == "__main__":
    run_evaluation()
