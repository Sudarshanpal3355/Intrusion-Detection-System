import os
import joblib

def ensure_dirs():
    """
    Ensure required project directories exist.
    """
    os.makedirs("models", exist_ok=True)
    os.makedirs("results", exist_ok=True)

def save(obj, path):
    """
    Save any Python object using joblib.
    Automatically creates parent directories if needed.
    """
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    joblib.dump(obj, path)
    print(f"💾 Saved: {path}")

def load(path):
    """
    Load a saved Python object.
    Raises clear error if file does not exist.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"❌ File not found: {path}")
    print(f"📂 Loaded: {path}")
    return joblib.load(path)
