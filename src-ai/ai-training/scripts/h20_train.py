import pandas as pd
import h2o
from h2o.automl import H2OAutoML
import json
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler

# Initialize H2O
h2o.init()

# Load the JSON data
data_file = 'C:/Users/26dwi/ENTRYL/src-ai/ai-training/extracted/extracted_data2.json'
with open(data_file, 'r') as f:
    data = json.load(f)
    df = pd.DataFrame(data)

# Handle missing values
df.dropna(subset=['Label'], inplace=True)
threshold = 0.5
df.dropna(thresh=int(threshold * len(df)), axis=1, inplace=True)

# Flatten the sections and imports
def flatten_json(row):
    if 'Sections' in row and isinstance(row['Sections'], list):
        for i, section in enumerate(row['Sections']):
            for key, value in section.items():
                row[f'Section_{i}_{key}'] = value
        del row['Sections']
    if 'Imports' in row and isinstance(row['Imports'], list):
        for i, imp in enumerate(row['Imports']):
            row[f'Import_{i}_DLL'] = imp['DLL']
            row[f'Import_{i}_Functions'] = ', '.join(imp['Functions'])
        del row['Imports']
    return row

# Apply flattening
df = df.apply(flatten_json, axis=1)

# Convert all non-numeric columns to strings for categorical handling
categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
for col in categorical_cols:
    df[col] = df[col].astype(str)

# Convert columns to numeric where possible
def convert_to_numeric(series):
    return pd.to_numeric(series, errors='coerce')

df = df.apply(convert_to_numeric)

# Standardize numeric features
numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns.tolist()
scaler = StandardScaler()
df[numeric_cols] = scaler.fit_transform(df[numeric_cols])

# Load into H2O for AutoML processing
df_h2o = h2o.H2OFrame(df)

# Split into training and test datasets
train, test = df_h2o.split_frame(ratios=[0.8], seed=123)

# Define the response column (Label) and feature columns (excluding Label)
y_col = 'Label'
X_cols = df_h2o.columns
X_cols.remove(y_col)

# Initialize and run AutoML
aml = H2OAutoML(max_models=100,  # Increased model limit
                 seed=42,
                 stopping_metric="AUC",
                 balance_classes=True,
                 max_runtime_secs=3600,  # Limit runtime for faster execution
                 nfolds=5)  # Enable cross-validation
aml.train(x=X_cols, y=y_col, training_frame=train)

# Show leaderboard
lb = aml.leaderboard
print(lb.head())

# Get the best model
best_model = aml.leader
print(f"Best Model: {best_model}")

# Predict on the test set
predictions = best_model.predict(test)
print(predictions)

# Save the model for future use
model_path = h2o.save_model(model=best_model, path="C:/Users/26dwi/ENTRYL/src-ai/ai-training/models", force=True)
print(f"Model saved at: {model_path}")

# Plot the performance metrics (AUC and accuracy)
lb_df = lb.as_data_frame()
plt.figure(figsize=(12, 6))
plt.plot(lb_df.index, lb_df['auc'], marker='o', label='AUC Score')
plt.plot(lb_df.index, lb_df['mse'], marker='o', label='Mean Squared Error')
plt.title('Model Performance Metrics')
plt.xlabel('Model Index')
plt.ylabel('Score')
plt.legend()
plt.grid()
plt.show()

# Shutdown H2O
h2o.shutdown(prompt=False)