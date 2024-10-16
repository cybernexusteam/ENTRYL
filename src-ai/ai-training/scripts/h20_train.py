import pandas as pd
import numpy as np
import h2o
from h2o.automl import H2OAutoML
import json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.feature_selection import VarianceThreshold

# Initialize H2O
h2o.init()

# Define the path to your extracted data
DATA_FILE = 'C:/Users/26dwi/ENTRYL/src-ai/ai-training/extracted/extracted_data3.json'

def load_and_preprocess_data(file_path):
    """Load and preprocess the extracted data."""
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    df = pd.json_normalize(data)
    
    # Handle nested structures
    for col in df.columns:
        if isinstance(df[col].iloc[0], (list, dict)):
            df[col] = df[col].astype(str)
    
    return df

def engineer_features(df):
    """Create new features and handle existing ones."""
    # Count the number of sections, imports, and exports
    df['SectionCount'] = df['Sections'].apply(lambda x: len(eval(x)) if isinstance(x, str) else 0)
    df['ImportCount'] = df['Imports'].apply(lambda x: len(eval(x)) if isinstance(x, str) else 0)
    df['ExportCount'] = df['Exports'].apply(lambda x: len(eval(x)) if isinstance(x, str) else 0)
    
    # Extract specific import DLLs often associated with malware
    suspicious_dlls = ['kernel32.dll', 'advapi32.dll', 'user32.dll', 'wininet.dll', 'ws2_32.dll']
    for dll in suspicious_dlls:
        df[f'Has_{dll}'] = df['Imports'].apply(lambda x: 1 if dll in str(x).lower() else 0)
    
    # Create features from file characteristics
    df['IsDLL'] = df['Characteristics'].apply(lambda x: 1 if x & 0x2000 else 0)
    df['IsExecutable'] = df['Characteristics'].apply(lambda x: 1 if x & 0x0002 else 0)
    
    # Handle entropy features
    if 'TotalEntropy' not in df.columns:
        df['TotalEntropy'] = df['Sections'].apply(lambda x: np.mean([s.get('Entropy', 0) for s in eval(x)]) if isinstance(x, str) else 0)
    
    # Create feature for presence of macros in OLE files
    df['HasMacros'] = df['Macros'].apply(lambda x: 0 if x == "No Macros stream found." else 1)
    
    return df

def prepare_data_for_h2o(df):
    """Prepare the DataFrame for H2O AutoML."""
    # Encode categorical variables
    le = LabelEncoder()
    categorical_columns = df.select_dtypes(include=['object']).columns
    for col in categorical_columns:
        df[col] = le.fit_transform(df[col].astype(str))
    
    # Handle missing values
    imputer = SimpleImputer(strategy='mean')
    df_imputed = pd.DataFrame(imputer.fit_transform(df), columns=df.columns)
    
    # Remove low variance features
    selector = VarianceThreshold()
    df_selected = pd.DataFrame(selector.fit_transform(df_imputed), columns=df_imputed.columns[selector.get_support()])
    
    return df_selected

# Load and preprocess the data
print("Loading and preprocessing data...")
df = load_and_preprocess_data(DATA_FILE)
df = engineer_features(df)
df = prepare_data_for_h2o(df)

# Split the data
train_df, valid_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df['Label'])

# Convert to H2OFrame
train_h2o = h2o.H2OFrame(train_df)
valid_h2o = h2o.H2OFrame(valid_df)

# Define features and target
y_col = 'Label'
X_cols = [col for col in train_h2o.columns if col != y_col]

# Define the AutoML model
aml = H2OAutoML(
    max_models=50,
    seed=42,
    balance_classes=True,
    max_runtime_secs=7200,  # 2 hours runtime
    stopping_metric="AUC",
    sort_metric="AUC",
    exclude_algos=["DeepLearning"],  # Exclude deep learning for faster training
)

# Train the model
print("Training the model...")
aml.train(x=X_cols, y=y_col, training_frame=train_h2o, validation_frame=valid_h2o)

# Print the leaderboard
print("Model Training Complete. Leaderboard:")
leaderboard = aml.leaderboard
print(leaderboard.head(rows=leaderboard.nrows))

# Get the best model
best_model = aml.leader
print(f"\nBest Model: {best_model}")

# Make predictions on the validation set
print("\nMaking predictions on validation set...")
predictions = best_model.predict(valid_h2o)
print(predictions.head())

# Evaluate the model
print("\nModel Performance:")
performance = best_model.model_performance(valid_h2o)
print(performance)

# Save the model
model_path = h2o.save_model(model=best_model, path="C:/Users/26dwi/ENTRYL/src-ai/ai-training/models", force=True)
print(f"\nModel saved to: {model_path}")

# Shutdown H2O
h2o.shutdown(prompt=False)