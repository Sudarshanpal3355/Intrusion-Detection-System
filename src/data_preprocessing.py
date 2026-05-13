import pandas as pd
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from utils import ensure_dirs, save


def preprocess(train_path, test_path):
    print("📥 Loading datasets...")
    train = pd.read_csv(train_path)
    test = pd.read_csv(test_path)

    print("🧹 Removing duplicates...")
    train.drop_duplicates(inplace=True)
    test.drop_duplicates(inplace=True)

    print("🩹 Handling missing values...")
    train.fillna(0, inplace=True)
    test.fillna(0, inplace=True)

    print("🎯 Separating labels...")
    y_train = train["label"]
    y_test = test["label"]

    X_train = train.drop(columns=["label"])
    X_test = test.drop(columns=["label"])

    # =====================================================
    # 🔥 CRITICAL: SAVE FEATURE SCHEMA
    # =====================================================
    feature_names = X_train.columns.tolist()

    # Identify categorical & numerical columns
    categorical_cols = X_train.select_dtypes(include=["object"]).columns.tolist()
    numerical_cols = X_train.select_dtypes(exclude=["object"]).columns.tolist()

    print(f"🔤 Categorical columns ({len(categorical_cols)}): {categorical_cols}")
    print(f"🔢 Numerical columns: {len(numerical_cols)}")

    # =====================================================
    # 🔥 SAVE CATEGORICAL VALUE MAP (FOR LIVE SIMULATION)
    # =====================================================
    categorical_values = {
        col: X_train[col].astype(str).unique().tolist()
        for col in categorical_cols
    }

    # =====================================================
    # Column Transformer
    # =====================================================
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), numerical_cols),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), categorical_cols),
        ],
        remainder="drop"
    )

    print("⚙️ Encoding + scaling features...")
    X_train_processed = preprocessor.fit_transform(X_train)
    X_test_processed = preprocessor.transform(X_test)

    # =====================================================
    # SAVE ARTIFACTS
    # =====================================================
    ensure_dirs()

    save(preprocessor, "models/encoder_scaler.pkl")
    save(X_train_processed, "models/X_train.pkl")
    save(X_test_processed, "models/X_test.pkl")
    save(y_train, "models/y_train.pkl")
    save(y_test, "models/y_test.pkl")

    # 🔥 NEW (ABSOLUTELY REQUIRED)
    save(feature_names, "models/feature_names.pkl")
    save(categorical_cols, "models/categorical_cols.pkl")
    save(categorical_values, "models/categorical_values.pkl")

    print("💾 Saved artifacts:")
    print("   ├── encoder_scaler.pkl")
    print("   ├── X_train.pkl / X_test.pkl")
    print("   ├── y_train.pkl / y_test.pkl")
    print("   ├── feature_names.pkl")
    print("   ├── categorical_cols.pkl")
    print("   └── categorical_values.pkl")

    print("🎉 Data preprocessing completed successfully!")

    return X_train_processed, X_test_processed, y_train, y_test, preprocessor


# =====================================================
# ENTRY POINT
# =====================================================
if __name__ == "__main__":
    print("🚀 Data preprocessing started...")
    preprocess(
        "data/UNSW_NB15_training-set.csv",
        "data/UNSW_NB15_testing-set.csv"
    )
