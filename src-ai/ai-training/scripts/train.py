import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import json


data_file = '/home/pengu/ENTRYL/src-ai/ai-training/extracted/extracted_data.json'  # Path to your JSON file (PASTE UR OWN PATH TESTING ONLY)

with open(data_file, 'r') as f:
    data = json.load(f)
    df = pd.DataFrame(data)

print("\nChecking for missing values...")
missing_values = df.isnull().sum()
print(missing_values[missing_values > 0])  # Print only columns with missing values

# Handle missing values
df.dropna(subset=['Label'], inplace=True)

threshold = 0.5  # 50% threshold
df.dropna(thresh=int(threshold * len(df)), axis=1, inplace=True)

print(f"Data shape after handling missing values: {df.shape}")

if 'Label' not in df.columns:
    raise ValueError("Error: 'Label' column is missing from the data.")

# Separate Features and Labels
X = df.drop(columns=['Label'])  # Features
y = df['Label']  # Labels

# Convert columns to numeric where possible and catch exceptions
def convert_to_numeric(series):
    try:
        return pd.to_numeric(series)
    except (ValueError, TypeError):
        return series

# Apply conversion function to all columns
for col in X.columns:
    X[col] = convert_to_numeric(X[col])

# Identify categorical columns that are of type object
categorical_cols = X.select_dtypes(include=['object']).columns.tolist()

# Check for lists in categorical columns and flatten them
for col in categorical_cols:
    if X[col].apply(lambda x: isinstance(x, list)).any():
        print(f"Warning: Column '{col}' contains lists. Flattening the values.")
        X[col] = X[col].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x)

# One-hot encode!!!
X = pd.get_dummies(X, columns=categorical_cols, drop_first=True)

# Check if there are any samples available
if X.shape[0] == 0:
    raise ValueError("Error: No data samples found in features after processing.")

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Feature Scaling
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train the RFC
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train_scaled, y_train)

# predictions
y_pred = rf_model.predict(X_test_scaled)

# report output
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

import joblib
joblib.dump(rf_model, 'rf_model.pkl')
