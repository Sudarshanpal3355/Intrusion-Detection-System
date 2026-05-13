import os
import joblib

def ensure_dirs():
    """Ensure required directories exist"""
    os.makedirs("models", exist_ok=True)
    os.makedirs("results", exist_ok=True)

def save(obj, path):
    """Save object using joblib"""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    joblib.dump(obj, path)
    print(f"💾 Saved: {path}")

def load(path):
    """Load object using joblib"""
    if not os.path.exists(path):
        raise FileNotFoundError(f"❌ File not found: {path}")
    print(f"📂 Loaded: {path}")
    return joblib.load(path)
