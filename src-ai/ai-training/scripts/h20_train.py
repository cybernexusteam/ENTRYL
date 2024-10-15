import pandas as pd
import h2o
from h2o.automl import H2OAutoML
import json

# Initialize H2O
h2o.init()

# Load data
data_file = 'C:/Users/26dwi/ENTRYL/src-ai/ai-training/extracted/extracted_data.json'

with open(data_file, 'r') as f:
    data = json.load(f)
    df = pd.DataFrame(data)

# Handle missing values
df.dropna(subset=['Label'], inplace=True)
threshold = 0.5  # 50% threshold for missing values in a column
df.dropna(thresh=int(threshold * len(df)), axis=1, inplace=True)

# Function to flatten sections and imports
def flatten_features(row):
    # Flatten sections
    if 'Sections' in row and isinstance(row['Sections'], list):
        for i, section in enumerate(row['Sections']):
            for key, value in section.items():
                row[f'Section_{i}_{key}'] = value
        del row['Sections']  # Remove the original nested structure

    # Flatten imports
    if 'Imports' in row and isinstance(row['Imports'], list):
        for i, imp in enumerate(row['Imports']):
            row[f'Import_{i}_DLL'] = imp['DLL']
            row[f'Import_{i}_Functions'] = ', '.join(imp['Functions'])
        del row['Imports']  # Remove the original nested structure
    
    return row

# Apply flattening to each row
flattened_data = df.apply(flatten_features, axis=1)

# Convert categorical columns to string if not numeric
categorical_cols = flattened_data.select_dtypes(include=['object']).columns.tolist()
for col in categorical_cols:
    flattened_data[col] = flattened_data[col].astype(str)

# Convert columns to numeric where possible
def convert_to_numeric(series):
    return pd.to_numeric(series, errors='coerce')  # Convert to numeric, replacing errors with NaN

for col in flattened_data.columns:
    flattened_data[col] = convert_to_numeric(flattened_data[col])

# Combine X and y back into a single DataFrame for H2O
flattened_data['Label'] = df['Label']
df_h2o = h2o.H2OFrame(flattened_data)

# Split the dataset
train, test = df_h2o.split_frame(ratios=[0.8], seed=42)

# Specify the response and feature columns
y_col = 'Label'
X_cols = df_h2o.columns
X_cols.remove(y_col)

# Run H2O AutoML
aml = H2OAutoML(max_models=20, seed=42, stopping_metric="AUC")
aml.train(x=X_cols, y=y_col, training_frame=train)

# View the AutoML leaderboard
leaderboard = aml.leaderboard
print(leaderboard.head())

# Best model from AutoML
best_model = aml.leader
print(f"Best Model: {best_model}")

# Predictions on the test set
predictions = best_model.predict(test)
print(predictions)

# Export the model for future use
model_path = h2o.save_model(model=best_model, path="C:/Users/26dwi/ENTRYL/src-ai/ai-training/models", force=True)
print(f"Model saved to: {model_path}")

# Shutdown the H2O cluster
h2o.shutdown(prompt=False)
