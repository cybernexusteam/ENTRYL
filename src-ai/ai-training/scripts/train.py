import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import json

# Load Data from JSON
data_file = '/home/pengu/ENTRYL/src-ai/ai-training/scripts/extracted_data.json'  # Path to your JSON file (PASTE UR OWN PATH TESTING ONLY)

# Load the JSON data into a DataFrame
with open(data_file, 'r') as f:
    data = json.load(f)
    df = pd.DataFrame(data)

# Check for Missing Values
print("\nChecking for missing values...")
missing_values = df.isnull().sum()
print(missing_values[missing_values > 0])  # Print only columns with missing values

# Handle missing values
df.dropna(subset=['Label'], inplace=True)

# Drop columns with excessive missing values
threshold = 0.5  # 50% threshold
df.dropna(thresh=int(threshold * len(df)), axis=1, inplace=True)

# Check shape after handling missing values
print(f"Data shape after handling missing values: {df.shape}")

# Ensure the Label column exists
if 'Label' not in df.columns:
    raise ValueError("Error: 'Label' column is missing from the data.")

# Separate Features and Labels
X = df.drop(columns=['Label'])  # Features
y = df['Label']  # Labels

# Convert columns to numeric where possible and catch exceptions
def convert_to_numeric(series):
    # Attempt to convert and return a numeric series; if fails, return original
    try:
        return pd.to_numeric(series)
    except (ValueError, TypeError):
        return series  # Return original series if it cannot be converted

# Apply conversion function to all columns
for col in X.columns:
    X[col] = convert_to_numeric(X[col])

# Identify categorical columns that are of type object
categorical_cols = X.select_dtypes(include=['object']).columns.tolist()

# Check for lists in categorical columns and flatten them
for col in categorical_cols:
    if X[col].apply(lambda x: isinstance(x, list)).any():
        print(f"Warning: Column '{col}' contains lists. Flattening the values.")
        # Convert list values to a string (or any appropriate representation)
        X[col] = X[col].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x)

# One-hot encode categorical features
X = pd.get_dummies(X, columns=categorical_cols, drop_first=True)

# Check if there are any samples available
if X.shape[0] == 0:
    raise ValueError("Error: No data samples found in features after processing.")

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Feature Scaling
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)  # Fit and transform training data
X_test_scaled = scaler.transform(X_test)  # Transform test data

# Train Random Forest Classifier
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train_scaled, y_train)

# Make Predictions
y_pred = rf_model.predict(X_test_scaled)

# Generate Classification Report
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save the Model (optional)
import joblib
joblib.dump(rf_model, 'rf_model.pkl')  # Save the trained model
