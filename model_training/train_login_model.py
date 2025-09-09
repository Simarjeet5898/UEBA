import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from tqdm import tqdm


# === Load Dataset ===
# csv_path = "datasets/abnormal_login_dataset.csv"
# csv_path = "datasets/synthetic_login_dataset.csv"
csv_path = "datasets/rba-dataset/rba-dataset.csv"

df = pd.read_csv(csv_path)
df = pd.read_csv(csv_path)

print(df.columns)
print(df.head())

# === Drop rows with missing values (if any) ===
# df = df.dropna()
df.drop(columns=['session_duration_seconds'], inplace=True)

# === Encode categorical columns ===
categorical_cols = ['username', 'auth_type', 'hostname', 'remote_ip', 'day_of_week']
label_encoders = {}

for col in categorical_cols:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    label_encoders[col] = le  # Save for inference time if needed

# === Features and Target ===
X = df.drop(columns=["is_abnormal", "login_time"])  # Remove target and timestamp
y = df["is_abnormal"]


# print("✅ X shape:", X.shape)
# print("✅ y shape:", y.shape)
# print("📌 X preview:\n", X.head())
# print("📌 y preview:\n", y.head())

# === Train/Test Split ===

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# === Train Model ===
# model = RandomForestClassifier(n_estimators=100, random_state=42)
model = RandomForestClassifier(n_estimators=1, warm_start=True)
n_trees = 100  # or any number you want
print(f"🚀 Starting training with {n_trees} trees...")

# model.fit(X_train, y_train)
# Progress bar for training
for i in tqdm(range(1, n_trees + 1), desc="🌲 Training Random Forest"):
    model.set_params(n_estimators=i)
    model.fit(X_train, y_train)

print("✅ Model training completed.")

# === Evaluate ===
y_pred = model.predict(X_test)
print("\n📊 Classification Report:\n", classification_report(y_test, y_pred))

# === Save Model ===
os.makedirs("ai_models", exist_ok=True)
model_path = "ai_models/abnormal_login_model.pkl"
joblib.dump(model, model_path)

print(f"\n✅ Model saved to: {model_path}")
