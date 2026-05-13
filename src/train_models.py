import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import os

def apply_feature_selector(X, selector):
    X_var = selector["variance_selector"].transform(X)
    X_final = X_var[:, selector["top_feature_indices"]]
    return X_final

if __name__ == "__main__":
    print("🚀 Model training started...")

    # ============================
    # Load data
    # ============================
    X_train = joblib.load("models/X_train.pkl")
    X_test = joblib.load("models/X_test.pkl")
    y_train = joblib.load("models/y_train.pkl")
    y_test = joblib.load("models/y_test.pkl")

    # Load preprocessor + selector
    preprocessor = joblib.load("models/encoder_scaler.pkl")
    selector = joblib.load("models/feature_selector.pkl")

    # ============================
    # Apply feature engineering
    # ============================
    X_train = apply_feature_selector(X_train, selector)
    X_test = apply_feature_selector(X_test, selector)

    print(f"📐 Features after selection: {X_train.shape[1]}")

    # ============================
    # Load class weights
    # ============================
    class_weights = joblib.load("models/class_weights.pkl")

    # ============================
    # Train Random Forest
    # ============================
    print("🌲 Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight=class_weights
    )
    rf.fit(X_train, y_train)

    # ============================
    # Train Logistic Regression
    # ============================
    print("📈 Training Logistic Regression...")
    lr = LogisticRegression(
        max_iter=1000,
        class_weight=class_weights,
        n_jobs=-1
    )
    lr.fit(X_train, y_train)

    # ============================
    # Evaluate models
    # ============================
    rf_acc = accuracy_score(y_test, rf.predict(X_test))
    lr_acc = accuracy_score(y_test, lr.predict(X_test))

    print(f"✅ Random Forest Accuracy: {rf_acc:.4f}")
    print(f"✅ Logistic Regression Accuracy: {lr_acc:.4f}")

    # ============================
    # Select best model
    # ============================
    best_model = rf if rf_acc >= lr_acc else lr

    os.makedirs("models", exist_ok=True)
    joblib.dump(best_model, "models/final_ids_model.pkl")
    joblib.dump(lr, "models/baseline_model.pkl")

    print("💾 Models saved:")
    print("   ├── models/final_ids_model.pkl")
    print("   └── models/baseline_model.pkl")

    # =====================================================
    # 🔥 SAVE FINAL FEATURE NAMES (PROPER SHAP ALIGNMENT)
    # =====================================================

    # 1️⃣ Get feature names after preprocessing
    num_cols = preprocessor.transformers_[0][2]
    cat_cols = preprocessor.transformers_[1][2]

    cat_encoder = preprocessor.named_transformers_["cat"]
    cat_feature_names = cat_encoder.get_feature_names_out(cat_cols)

    all_feature_names = list(num_cols) + list(cat_feature_names)

    # 2️⃣ Apply variance selector mask
    variance_mask = selector["variance_selector"].get_support()
    post_variance_features = [
        name for name, keep in zip(all_feature_names, variance_mask) if keep
    ]

    # 3️⃣ Apply top feature indices
    top_feature_indices = selector["top_feature_indices"]
    final_feature_names = [
        post_variance_features[i] for i in top_feature_indices
    ]

    # 4️⃣ Save
    joblib.dump(final_feature_names, "models/final_feature_names.pkl")

    print("✅ Saved models/final_feature_names.pkl")
    print("🎉 Model training completed successfully!")