import numpy as np
from collections import Counter
from sklearn.utils.class_weight import compute_class_weight
from utils import load, save, ensure_dirs


if __name__ == "__main__":
    print("🚀 Imbalance handling using class weights...")

    # 📁 Ensure required directories exist
    ensure_dirs()

    # 📂 Load training labels
    y_train = load("models/y_train.pkl")

    print("📊 Original class distribution:", Counter(y_train))

    # ⚖️ Compute class weights
    classes = np.unique(y_train)
    weights = compute_class_weight(
        class_weight="balanced",
        classes=classes,
        y=y_train
    )

    class_weights = dict(zip(classes, weights))

    print("⚖️ Computed class weights:")
    for cls, weight in class_weights.items():
        print(f"   Class {cls}: {weight:.4f}")

    # 💾 Save class weights
    save(class_weights, "models/class_weights.pkl")

    print("🎉 Imbalance handling completed successfully!")
