import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.metrics import classification_report
import pickle
import json
import os

# Load data
data_file = 'C:/Users/26dwi/ENTRYL/src-ai/ai-training/extracted/extracted_data.json'

with open(data_file, 'r') as f:
    data = json.load(f)
    df = pd.DataFrame(data)

# Handle missing values
df.dropna(subset=['Label'], inplace=True)
threshold = 0.5  # 50% threshold
df.dropna(thresh=int(threshold * len(df)), axis=1, inplace=True)

# Separate Features and Labels
X = df.drop(columns=['Label'])  # Features
y = df['Label']  # Labels

# Convert columns to numeric where possible
def convert_to_numeric(series):
    try:
        return pd.to_numeric(series)
    except (ValueError, TypeError):
        return series

for col in X.columns:
    X[col] = convert_to_numeric(X[col])

# Identify categorical columns that are of type object or contain lists
categorical_cols = X.select_dtypes(include=['object']).columns.tolist()

# Convert lists to strings for OneHotEncoder
for col in categorical_cols:
    if X[col].apply(lambda x: isinstance(x, list)).any():
        print(f"Warning: Column '{col}' contains lists. Converting lists to strings.")
        X[col] = X[col].apply(lambda x: ', '.join(map(str, x)) if isinstance(x, list) else x)

# One-Hot Encoder for categorical features
categorical_features = X.select_dtypes(include=['object']).columns.tolist()

# Numerical features
numerical_features = X.select_dtypes(include=['number']).columns.tolist()

# Column transformer with OneHotEncoder and StandardScaler
preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), numerical_features),
        ('cat', OneHotEncoder(sparse_output=False, handle_unknown='ignore'), categorical_features)
    ])

# Split the dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Preprocessing the training data
X_train_preprocessed = preprocessor.fit_transform(X_train)
X_test_preprocessed = preprocessor.transform(X_test)

# Define LightGBM model with default parameters for initial testing
lgb_model = LGBMClassifier(
    boosting_type='gbdt',  # Gradient boosting decision tree
    objective='binary',    # Binary classification (malware vs benign)
    n_jobs=-1,             # Utilize all CPU cores for parallel processing
    random_state=42,       # For reproducibility
)

# Hyperparameter Tuning with GridSearchCV
param_grid = {
    'n_estimators': [1000],  # Setting to 1000 as requested
    'learning_rate': [0.01, 0.1, 0.05],
    'max_depth': [-1, 10, 20],  # -1 for no limit on depth
    'num_leaves': [31, 50, 100],  # Control tree complexity
    'min_child_samples': [10, 20, 30],  # Minimum data in leaf node
    'subsample': [0.8, 1.0]  # Fraction of data to be used for training
}

# Set up GridSearchCV to find the best hyperparameters
grid_search = GridSearchCV(
    lgb_model,
    param_grid,
    cv=5,  # 5-fold cross-validation
    scoring='f1_weighted',  # F1-score weighted for classification performance
    n_jobs=-1  # Parallel execution for the grid search
)

# Train the model with GridSearchCV
grid_search.fit(X_train_preprocessed, y_train)

# Best model from grid search
best_lgb_model = grid_search.best_estimator_
print("Best parameters found: ", grid_search.best_params_) 

# Predictions
y_pred = best_lgb_model.predict(X_test_preprocessed)

# Classification Report
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save the model and preprocessor
output_path_model = "C:/Users/26dwi/ENTRYL/src-ai/ai-training/models/gb_model04.pkl"
output_path_preprocessor = "C:/Users/26dwi/ENTRYL/src-ai/ai-training/models/preprocessor02.pkl"

# Save the model
with open(output_path_model, 'wb') as f:
    pickle.dump(best_lgb_model, f)

# Save the preprocessor
with open(output_path_preprocessor, 'wb') as f:
    pickle.dump(preprocessor, f)

print("Model and preprocessor saved successfully.")
