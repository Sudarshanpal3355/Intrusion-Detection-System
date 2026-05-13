import numpy as np
from sklearn.feature_selection import VarianceThreshold
from sklearn.ensemble import RandomForestClassifier
from utils import load, save, ensure_dirs


if __name__ == "__main__":
    print("🚀 Feature engineering started...")

    # 📂 Load data
    X_train = load("models/X_train.pkl")
    y_train = load("models/y_train.pkl")

    print(f"📐 Original feature count: {X_train.shape[1]}")

    # ============================
    # STEP 1: Remove low-variance features
    # ============================
    print("🧹 Removing low-variance features...")
    var_selector = VarianceThreshold(threshold=0.01)
    X_var = var_selector.fit_transform(X_train)

    print(f"📉 Features after variance threshold: {X_var.shape[1]}")

    # ============================
    # STEP 2: Feature importance via Random Forest
    # ============================
    print("🌲 Computing feature importance using Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_var, y_train)

    importances = rf.feature_importances_

    # ============================
    # STEP 3: Select top features
    # ============================
    top_k = int(0.5 * len(importances))  # keep top 50%
    top_indices = np.argsort(importances)[-top_k:]

    print(f"⭐ Selected top {top_k} important features")

    # ============================
    # STEP 4: Save feature selector
    # ============================
    ensure_dirs()

    feature_selector = {
        "variance_selector": var_selector,
        "top_feature_indices": top_indices
    }

    save(feature_selector, "models/feature_selector.pkl")

    print("🎉 Feature engineering completed successfully!")
