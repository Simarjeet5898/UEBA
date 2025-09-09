import os
from pathlib import Path
import kagglehub

# === Settings ===
dataset_name = "dasgroup/rba-dataset"
dataset_dir = Path("datasets")
target_path = dataset_dir / "rba-dataset"           # Risk based authentication

# === Ensure directory exists ===
dataset_dir.mkdir(parents=True, exist_ok=True)

# === Download ===
print("⬇️  Downloading dataset from Kaggle...")
downloaded_path = kagglehub.dataset_download(dataset_name)

# === Move to datasets folder ===
if not target_path.exists():
    os.system(f"cp -r '{downloaded_path}' '{target_path}'")
    print(f"✅ Dataset saved to: {target_path}")
else:
    print(f"ℹ️ Dataset already exists at: {target_path}")
