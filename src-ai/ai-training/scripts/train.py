import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_curve, auc
import joblib
import json
import matplotlib.pyplot as plt

# Load data
data_file = '/home/pengu/ENTRYL/src-ai/ai-training/extracted/extracted_data.json'  # Path to your JSON file

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

# One-hot encode categorical columns
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

# Hyperparameter Tuning with GridSearchCV
param_grid = {
    'n_estimators': [100],
    'max_depth': [None, 10, 20, 30],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4],
    'max_features': ['auto', 'sqrt', 'log2']
}

grid_search = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, cv=5, scoring='f1_weighted', n_jobs=-1)
grid_search.fit(X_train_scaled, y_train)

# Best model from grid search
rf_model = grid_search.best_estimator_
print("Best parameters found: ", grid_search.best_params_)

# Predictions
y_pred = rf_model.predict(X_test_scaled)

# Report output
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# ROC Curve
y_probs = rf_model.predict_proba(X_test_scaled)[:, 1]
fpr, tpr, thresholds = roc_curve(y_test, y_probs, pos_label='malicious')
roc_auc = auc(fpr, tpr)

# Plot ROC Curve
plt.figure()
plt.plot(fpr, tpr, color='blue', label='ROC curve (area = %0.2f)' % roc_auc)
plt.plot([0, 1], [0, 1], color='red', linestyle='--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic')
plt.legend(loc='lower right')
plt.show()

# Save model
joblib.dump(rf_model, 'rf_model.pkl')
