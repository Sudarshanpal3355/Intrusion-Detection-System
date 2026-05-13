import numpy as np
from sklearn.metrics import mean_squared_error
from utils import load, save, ensure_dirs


def risk_level(score: float) -> str:
    """
    Convert anomaly score into risk level.
    Higher score => more anomalous.
    """
    if score < 0.3:
        return "Low"
    elif score < 0.6:
        return "Medium"
    else:
        return "High"


if __name__ == "__main__":
    print("🚀 Anomaly detection started...")

    ensure_dirs()

    # ============================
    # Load required artifacts
    # ============================
    X_train = load("models/X_train.pkl")
    X_test = load("models/X_test.pkl")

    selector = load("models/feature_selector.pkl")

    # Apply same feature selection
    X_train_var = selector["variance_selector"].transform(X_train)
    X_train_sel = X_train_var[:, selector["top_feature_indices"]]

    X_test_var = selector["variance_selector"].transform(X_test)
    X_test_sel = X_test_var[:, selector["top_feature_indices"]]

    print(f"📐 Features used: {X_train_sel.shape[1]}")

    # ============================
    # Simple Autoencoder-like anomaly score
    # (reconstruction error simulation)
    # ============================
    print("🔍 Computing anomaly scores...")

    train_mean = np.mean(X_train_sel, axis=0)

    train_scores = np.mean((X_train_sel - train_mean) ** 2, axis=1)
    test_scores = np.mean((X_test_sel - train_mean) ** 2, axis=1)

    # Normalize scores (0–1)
    max_score = max(train_scores.max(), test_scores.max())
    train_scores /= max_score
    test_scores /= max_score

    # ============================
    # Save results
    # ============================
    save(train_scores, "models/train_anomaly_scores.pkl")
    save(test_scores, "models/test_anomaly_scores.pkl")

    print("🎉 Anomaly detection completed successfully!")

    # Example output
    example_score = float(test_scores[0])
    print(f"🧪 Example anomaly score: {example_score:.4f}")
    print(f"⚠️ Risk level: {risk_level(example_score)}")
