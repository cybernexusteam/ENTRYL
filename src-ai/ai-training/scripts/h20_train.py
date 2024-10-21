import pandas as pd
import numpy as np
import h2o
from h2o.automl import H2OAutoML
import json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc, confusion_matrix, precision_recall_curve
import seaborn as sns
import os
import tensorflow as tf

h2o.init(max_mem_size="8G")  # Increase memory allocation to 8GB for longer training

DATA_FILE = 'C:/Users/26dwi/ENTRYL/src-ai/ai-training/extracted/extracted_features02.json'
OUTPUT_DIR = 'C:/Users/26dwi/ENTRYL/src-ai/ai-training/models'

def load_data(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return pd.json_normalize(data)

def preprocess_data(df):
    # Convert all object columns to strings for consistent processing
    for col in df.columns:
        if df[col].dtype == 'object':
            df[col] = df[col].astype(str)
    # Replace missing values with a placeholder
    imputer = SimpleImputer(strategy='constant', fill_value='missing')
    df_imputed = pd.DataFrame(imputer.fit_transform(df), columns=df.columns)
    return df_imputed

def engineer_features(df):
    # Feature engineering for section, import, and export counts
    def safe_len(x):
        try:
            return len(eval(x)) if pd.notna(x) and x not in ['nan', 'missing'] else 0
        except:
            return 0

    df['SectionCount'] = df['Sections'].apply(safe_len)
    df['ImportCount'] = df['Imports'].apply(safe_len)
    df['ExportCount'] = df['Exports'].apply(safe_len)

    # Extract suspicious functions
    def extract_suspicious_functions(imports):
        try:
            imports_list = eval(imports)
            return [func for entry in imports_list for func in entry.get('Functions', [])]
        except:
            return []

    df['FunctionImports'] = df['Imports'].apply(extract_suspicious_functions)

    # Flag suspicious API usage
    suspicious_functions = ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory']
    for func in suspicious_functions:
        df[f'Uses_{func}'] = df['FunctionImports'].apply(lambda funcs: 1 if func in funcs else 0)

    # Flags for DLLs and executables
    df['IsDLL'] = df['Characteristics'].apply(lambda x: 1 if pd.notna(x) and x not in ['missing', 'nan'] and int(float(x)) & 0x2000 else 0)
    df['IsExecutable'] = df['Characteristics'].apply(lambda x: 1 if pd.notna(x) and x not in ['missing', 'nan'] and int(float(x)) & 0x0002 else 0)

    # Compute mean entropy for sections
    df['TotalEntropy'] = df['Sections'].apply(lambda x: 
        np.mean([float(s.get('Entropy', 0)) for s in eval(x)]) if isinstance(x, str) and x not in ['nan', 'missing'] else 0)

    # Drop the original columns that are no longer needed
    drop_columns = ['Imports', 'Exports', 'Sections', 'FunctionImports']
    df.drop(columns=drop_columns, inplace=True)

    return df

def encode_categorical(df):
    # Label encode categorical variables
    le = LabelEncoder()
    for col in df.select_dtypes(include=['object']):
        df[col] = le.fit_transform(df[col].astype(str))
    return df

def prepare_data_for_h2o(df):
    df_encoded = encode_categorical(df)
    return h2o.H2OFrame(df_encoded)

def train_model(train, valid, y_col, X_cols):
    # AutoML setup excluding DeepLearning models for faster training
    aml = H2OAutoML(
        max_models=150,
        seed=42,
        balance_classes=True,
        max_runtime_secs=14400,  # 4 hours
        stopping_metric="AUC",
        sort_metric="AUC",
        exclude_algos=["DeepLearning"],  # Exclude deep learning models
        project_name="MalwareDetection",
        nfolds=5,
        keep_cross_validation_predictions=True,
        keep_cross_validation_models=True,
        verbosity="info"
    )

    # Train the model
    aml.train(x=X_cols, y=y_col, training_frame=train, validation_frame=valid)
    return aml

def save_model_and_results(aml, valid, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    if aml.leader is not None:
        model_path = h2o.save_model(model=aml.leader, path=output_dir, force=True)
        print(f"Model saved to: {model_path}")
        
        # Save model performance on validation data
        with open(os.path.join(output_dir, 'model_performance.txt'), 'w') as f:
            f.write(str(aml.leader.model_performance(valid)))
    else:
        print("No models were trained successfully. Unable to save model or performance metrics.")

def plot_results(aml, valid, y_col, output_dir):
    if aml.leader is None:
        print("No models were trained successfully. Unable to plot results.")
        return

    # Generate predictions and plot ROC curve, PR curve, and confusion matrix
    valid_pred = aml.leader.predict(valid)
    valid_pred = valid_pred.as_data_frame()['p1']
    valid_true = valid[y_col].as_data_frame().values.ravel()

    # ROC curve
    fpr, tpr, _ = roc_curve(valid_true, valid_pred)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(10, 6))
    plt.plot(fpr, tpr, color='blue', lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='red', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.legend(loc='lower right')
    plt.savefig(os.path.join(output_dir, 'roc_curve.png'))
    plt.close()

    # Precision-Recall curve
    precision, recall, _ = precision_recall_curve(valid_true, valid_pred)
    plt.figure(figsize=(10, 6))
    plt.plot(recall, precision, color='green', lw=2)
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.savefig(os.path.join(output_dir, 'precision_recall_curve.png'))
    plt.close()

    # Confusion Matrix
    conf_matrix = confusion_matrix(valid_true, (valid_pred > 0.5).astype(int))
    plt.figure(figsize=(8, 6))
    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues', cbar=False,
                xticklabels=['Non-Malware', 'Malware'],
                yticklabels=['Non-Malware', 'Malware'])
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.title('Confusion Matrix')
    plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'))
    plt.close()

def export_model_to_tensorflow(aml, output_dir):
    if aml.leader is not None:
        print(f"Leader model: {aml.leader.model_id}")
        
        model = aml.leader
        training_frame = model.training_frame
        features = training_frame.columns[:-1]
        X_train = training_frame[features].as_data_frame().values
        y_train = training_frame[model.actual_params['response_column']].as_data_frame().values

        # Build equivalent TensorFlow model
        tf_model = tf.keras.Sequential([
            tf.keras.layers.Input(shape=(X_train.shape[1],)),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')  # Binary classification
        ])

        # Compile the TensorFlow model
        tf_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

        # Train the TensorFlow model on the H2O data
        tf_model.fit(X_train, y_train, epochs=10, batch_size=32)

        # Save the TensorFlow model
        tf_model.save(os.path.join(output_dir, 'tensorflow_model.h5'))
        print(f"TensorFlow model saved to: {os.path.join(output_dir, 'tensorflow_model.h5')}")
    else:
        print("No leader model available for export.")

def main():
    df = load_data(DATA_FILE)
    df = preprocess_data(df)
    df = engineer_features(df)

    # Split data into train and validation sets
    train_df, valid_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df['Label'])

    train_h2o = prepare_data_for_h2o(train_df)
    valid_h2o = prepare_data_for_h2o(valid_df)

    y_col = 'Label'
    X_cols = [col for col in train_h2o.columns if col != y_col]

    # Convert Label column to categorical
    train_h2o[y_col] = train_h2o[y_col].asfactor()
    valid_h2o[y_col] = valid_h2o[y_col].asfactor()

    aml = train_model(train_h2o, valid_h2o, y_col, X_cols)

    save_model_and_results(aml, valid_h2o, OUTPUT_DIR)
    plot_results(aml, valid_h2o, y_col, OUTPUT_DIR)

    # Export to TensorFlow
    export_model_to_tensorflow(aml, OUTPUT_DIR)

    if aml.leaderboard is not None:
        print(aml.leaderboard.head(rows=10))
    else:
        print("No leaderboard available. AutoML may have failed to train any models.")

if __name__ == "__main__":
    main()
