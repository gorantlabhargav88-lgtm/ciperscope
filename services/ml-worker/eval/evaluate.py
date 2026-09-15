import json
import os
import unicodedata
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

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
    data_path = os.path.join(os.path.dirname(__file__), 'data', 'samples.json')
    if not os.path.exists(data_path):
        print(f"Error: {data_path} not found.")
        return

    with open(data_path, 'r', encoding='utf-8') as f:
        samples = json.load(f)

    print(f"Dataset Size: {len(samples)}")
    class_counts = {"LEGITIMATE": 0, "PHISHING_OR_SPAM": 0}
    for s in samples:
        class_counts[s["label"]] += 1
    print(f"Class Counts: {class_counts}")

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
    print(f"{'Threshold':<10} | {'Prec':<6} | {'Rec':<6} | {'F1':<6} | {'FPR':<6} | {'FNR':<6}")
    print("-" * 55)

    thresholds_to_test = [i/100.0 for i in range(101)]
    for t in thresholds_to_test:
        y_pred = [1 if s > t else 0 for s in y_scores]
        m = calc_metrics(y_true, y_pred)
        if t in [0.40, 0.85]:  # highlight production thresholds
            print(f"> {t:<8.2f} | {m['precision']:<6.4f} | {m['recall']:<6.4f} | {m['f1']:<6.4f} | {m['fpr']:<6.4f} | {m['fnr']:<6.4f} <--- PROD THRESHOLD")
        elif int(t*100) % 10 == 0:
            print(f"{t:<10.2f} | {m['precision']:<6.4f} | {m['recall']:<6.4f} | {m['f1']:<6.4f} | {m['fpr']:<6.4f} | {m['fnr']:<6.4f}")

    # Production Confusion Matrices
    print("\n--- CONFUSION MATRICES AT PROD THRESHOLDS ---")
    for t in [0.40, 0.85]:
        y_pred = [1 if s > t else 0 for s in y_scores]
        m = calc_metrics(y_true, y_pred)
        print(f"Threshold: {t}")
        print(f"TP: {m['tp']}, FP: {m['fp']}, TN: {m['tn']}, FN: {m['fn']}\n")

if __name__ == "__main__":
    run_evaluation()
