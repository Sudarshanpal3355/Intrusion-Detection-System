import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    ConfusionMatrixDisplay,
    roc_curve,
    auc
)
from utils import load, ensure_dirs


def apply_feature_selector(X, selector):
    X_var = selector["variance_selector"].transform(X)
    return X_var[:, selector["top_feature_indices"]]


if __name__ == "__main__":
    print("🚀 Evaluating trained IDS model...")

    ensure_dirs()

    # ============================
    # Load artifacts
    # ============================
    model = load("models/final_ids_model.pkl")
    X_test = load("models/X_test.pkl")
    y_test = load("models/y_test.pkl")
    selector = load("models/feature_selector.pkl")

    # Apply same feature selection as training
    X_test = apply_feature_selector(X_test, selector)

    print(f"📐 Features used for evaluation: {X_test.shape[1]}")

    # ============================
    # Predictions
    # ============================
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    # ============================
    # METRICS
    # ============================
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    with open("results/metrics.txt", "w") as f:
        f.write("Intrusion Detection System – Evaluation Metrics\n")
        f.write("---------------------------------------------\n")
        f.write(f"Accuracy  : {acc:.4f}\n")
        f.write(f"Precision : {prec:.4f}\n")
        f.write(f"Recall    : {rec:.4f}\n")
        f.write(f"F1-score  : {f1:.4f}\n")

    print("📄 Saved: results/metrics.txt")

    # ============================
    # CONFUSION MATRIX
    # ============================
    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm)
    disp.plot(cmap="Blues")
    plt.title("Confusion Matrix")
    plt.savefig("results/confusion_matrix.png")
    plt.close()

    print("🖼️ Saved: results/confusion_matrix.png")

    # ============================
    # ROC CURVE
    # ============================
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    roc_auc = auc(fpr, tpr)

    plt.figure()
    plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.4f}")
    plt.plot([0, 1], [0, 1], linestyle="--")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve")
    plt.legend()
    plt.savefig("results/roc_curve.png")
    plt.close()

    print("📈 Saved: results/roc_curve.png")

    # ============================
    # FEATURE IMPORTANCE
    # ============================
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_

        top_k = min(20, len(importances))
        idx = np.argsort(importances)[-top_k:]

        plt.figure(figsize=(8, 6))
        plt.barh(range(top_k), importances[idx])
        plt.yticks(range(top_k), [f"F{i}" for i in idx])
        plt.xlabel("Importance")
        plt.title("Top Feature Importances")
        plt.savefig("results/feature_importance.png")
        plt.close()

        print("📊 Saved: results/feature_importance.png")

    # ============================
    # LOG FILE
    # ============================
    with open("results/logs.txt", "w") as f:
        f.write("Evaluation completed successfully\n")
        f.write(f"Samples evaluated: {len(y_test)}\n")
        f.write(f"AUC: {roc_auc:.4f}\n")

    print("🧾 Saved: results/logs.txt")
    print("🎉 All evaluation outputs generated successfully!")
