import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.cluster import DBSCAN
import os
import matplotlib.pyplot as plt
import seaborn as sns
from tqdm import tqdm
from keras.models import Model
from keras.layers import Input, Dense
from sklearn.metrics import mean_squared_error
import numpy as np

# === Load datasets ===
train_path = "datasets/ueba/user_session_tracking_synthetic_training.csv"
test_path = "datasets/ueba/user_session_tracking_synthetic_testing.csv"

train_df = pd.read_csv(train_path, parse_dates=["login_time", "logout_time"])
test_df = pd.read_csv(test_path, parse_dates=["login_time", "logout_time"])

# === Drop irrelevant columns ===
cols_to_drop = ["mac_addresses", "hostname"]
train_df.drop(columns=cols_to_drop, inplace=True)
test_df.drop(columns=cols_to_drop, inplace=True)

# === Extract time-based features ===
for df in [train_df, test_df]:
    df["login_hour"] = df["login_time"].dt.hour
    df["logout_hour"] = df["logout_time"].dt.hour
    df["day_of_week"] = df["login_time"].dt.weekday  # 0 = Monday, 6 = Sunday

# === Encode categorical columns ===
categorical_cols = ["username", "auth_type", "remote_ip", "lan_ip", "source_os"]
label_encoders = {}


for col in categorical_cols:
    le = LabelEncoder()
    train_df[col] = le.fit_transform(train_df[col])
    label_encoders[col] = le

    # Create a mapping for the test set
    mapping = dict(zip(le.classes_, le.transform(le.classes_)))
    test_df[col] = test_df[col].map(mapping).fillna(-1).astype(int)


# === Select features for DBSCAN ===
features = [
    "login_hour",
    "logout_hour",
    "day_of_week",
    "session_duration_seconds",
    "auth_type",
    "remote_ip",
    "lan_ip"
]

X_train = train_df[features].copy()
X_test = test_df[features].copy()

# === Normalize (StandardScaler) ===
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)


# === Fit DBSCAN with tqdm ===
print(" Training DBSCAN on training data...")
dbscan = DBSCAN(eps=1.5, min_samples=5)
for _ in tqdm(range(1), desc="Fitting DBSCAN"):
    dbscan.fit(X_train_scaled)

# Labels assigned by DBSCAN (for training data)
train_labels = dbscan.labels_  # -1 = anomaly, 0+ = cluster ID

# Add labels back to DataFrame for inspection
train_df["cluster_label"] = train_labels
train_df["is_anomaly"] = (train_labels == -1).astype(int)

# Print summary
print(" DBSCAN fit completed on training data.")
print(" Cluster label counts:\n", pd.Series(train_labels).value_counts())
print(" Number of anomalies in training set:", train_df["is_anomaly"].sum())

# === Apply DBSCAN separately on testing data ===
test_dbscan = DBSCAN(eps=1.5, min_samples=5)
test_labels = test_dbscan.fit_predict(X_test_scaled)

test_df["cluster_label"] = test_labels
test_df["is_anomaly"] = (test_labels == -1).astype(int)

print(" DBSCAN applied to testing data.")
print(" Cluster label counts:\n", pd.Series(test_labels).value_counts())
print(" Number of anomalies in testing set:", test_df['is_anomaly'].sum())

# === Save full test results ===
os.makedirs("ai_models", exist_ok=True)
output_csv = "ai_models/dbscan_session_anomalies.csv"
test_df.to_csv(output_csv, index=False)
print(f"Full test session results (with anomalies flagged) saved to: {output_csv}")

# === Optional: Save only anomalies ===
anomalies_only = test_df[test_df["is_anomaly"] == 1]
anomaly_output_csv = "ai_models/dbscan_anomalies_only.csv"
anomalies_only.to_csv(anomaly_output_csv, index=False)
print(f" Anomalies-only file saved to: {anomaly_output_csv}")
print(f" Total anomalies detected: {len(anomalies_only)}")

print("\n🔍 Model Comparison on Test Data:")
print(" DBSCAN Anomalies:", test_df["is_anomaly"].sum())
# print(" Autoencoder Anomalies:", test_df["is_anomaly_autoencoder"].sum())
# print(" KNN Anomalies:", test_df["is_anomaly_knn"].sum())


# === Analyze Anomalies ===
anomalies_per_user = anomalies_only["username"].value_counts()
print(" Anomalies per user (Top 10):\n", anomalies_per_user.head(10))

plt.figure(figsize=(10, 6))
sns.heatmap(
    anomalies_only.pivot_table(
        index="login_hour",
        values="session_duration_seconds",
        aggfunc="mean"
    ),
    cmap="YlOrRd",
    annot=True,
    fmt=".0f"
)
plt.title(" Avg. Session Duration by Login Hour (Anomalies Only)")
plt.ylabel("Login Hour")
plt.xlabel("Avg. Session Duration")
plt.tight_layout()
plt.show()

ip_counts = anomalies_only["remote_ip"].value_counts()
print(" Most frequent remote IPs in anomalies:\n", ip_counts.head(10))
