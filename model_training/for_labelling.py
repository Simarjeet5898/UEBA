# import pandas as pd
# from datetime import datetime

# # Load existing testing dataset
# testing_path = 'datasets/ueba/user_session_tracking_synthetic_testing.csv'
# testing_df = pd.read_csv(testing_path, parse_dates=['login_time', 'logout_time'])

# # Define anomaly detection criteria
# def detect_anomaly(row):
#     # Odd hours (0 AM - 4 AM)
#     if row['login_time'].hour >= 0 and row['login_time'].hour <= 4:
#         return 1
#     # Very short session (<1 hour)
#     if row['session_duration_seconds'] < 3600:
#         return 1
#     # Very long session (>12 hours)
#     if row['session_duration_seconds'] > 43200:
#         return 1
#     # Zero-duration session
#     if row['session_duration_seconds'] == 0:
#         return 1
#     # Unknown IP or MAC (not localhost IP "127.0.1.1")
#     if row['remote_ip'] != '127.0.1.1':
#         return 1
#     # If none of the anomaly conditions met, label as normal
#     return 0

# # Apply anomaly detection to each row
# testing_df['is_anomaly'] = testing_df.apply(detect_anomaly, axis=1)

# # Save labeled dataset
# labeled_dataset_path = 'datasets/ueba/user_session_tracking_synthetic_testing_login.csv'
# testing_df.to_csv(labeled_dataset_path, index=False)

# print("✅ Labeled testing dataset saved successfully.")
# import pandas as pd

# # Load existing testing dataset
# testing_path = 'datasets/ueba/user_session_tracking_synthetic_testing.csv'
# testing_df = pd.read_csv(testing_path, parse_dates=['login_time'])

# # Define more stringent anomaly detection based on login_time
# def detect_anomaly_strict_login(row):
#     hour = row['login_time'].hour
#     weekday = row['login_time'].weekday()  # Monday=0, Sunday=6

#     # Late night login (12 AM to 6 AM)
#     if 0 <= hour < 6:
#         return 1
#     # Weekend login
#     if weekday >= 5:
#         return 1
#     # Off-hours login (before 8 AM or after 8 PM)
#     if hour < 8 or hour > 20:
#         return 1

#     return 0

# # Apply anomaly detection
# testing_df['is_anomaly'] = testing_df.apply(detect_anomaly_strict_login, axis=1)

# # Save labeled dataset
# labeled_dataset_path = 'datasets/ueba/user_session_tracking_login_strict.csv'
# testing_df.to_csv(labeled_dataset_path, index=False)

# print("✅ Strict login-time-based anomaly labels saved.")

import pandas as pd
import numpy as np

# === Load original testing dataset ===
testing_path = "/home/simar/Documents/UEBA_AI/Anomalous CPU consumption/datasets/ueba_testing_dataset_500_users.csv"
testing_df = pd.read_csv(testing_path, parse_dates=["login_time", "logout_time"])

# === Inject anomalies in 40% of rows ===
num_rows = len(testing_df)
anomaly_count = int(0.4 * num_rows)
anomaly_indices = np.random.choice(testing_df.index, size=anomaly_count, replace=False)

# Set high CPU usage (60%–90%) for injected anomalies
testing_df.loc[anomaly_indices, "cpu_usage"] = np.random.uniform(60, 90, size=anomaly_count)
testing_df["is_anomaly"] = 0
testing_df.loc[anomaly_indices, "is_anomaly"] = 1

# === Save updated dataset ===
labeled_path = "/home/simar/Documents/UEBA_AI/Anomalous CPU consumption/datasets/ueba_testing_dataset_500_users_labeled.csv"
testing_df.to_csv(labeled_path, index=False)

print(f"✅ Injected {anomaly_count} anomalies and saved updated dataset.")
