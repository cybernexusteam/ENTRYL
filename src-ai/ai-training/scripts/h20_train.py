import pandas as pd
import numpy as np
import h2o
from h2o.automl import H2OAutoML
import json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.feature_selection import VarianceThreshold
import shap
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc, confusion_matrix, precision_recall_curve
import seaborn as sns

h2o.init(max_mem_size="8G")

DATA_FILE = 'C:/Users/26dwi/ENTRYL/src-ai/ai-training/extracted/extracted_data3.json'

def load_and_preprocess_data(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    df = pd.json_normalize(data)
    for col in df.columns:
        if isinstance(df[col].iloc[0], (list, dict)):
            df[col] = df[col].astype(str)
    return df

def engineer_features(df):
    # Safely parse 'Sections' column without failing on NaN
    df['SectionCount'] = df['Sections'].apply(lambda x: len(eval(x)) if isinstance(x, str) and pd.notna(x) else 0)
    
    df['ImportCount'] = df['Imports'].apply(lambda x: len(eval(x)) if isinstance(x, str) and pd.notna(x) else 0)
    df['ExportCount'] = df['Exports'].apply(lambda x: len(eval(x)) if isinstance(x, str) and pd.notna(x) else 0)

    def extract_suspicious_functions(imports):
        functions = []
        if isinstance(imports, str) and pd.notna(imports):
            imports_list = eval(imports)
            for entry in imports_list:
                functions += entry.get('Functions', [])
        return functions

    df['FunctionImports'] = df['Imports'].apply(extract_suspicious_functions)

    suspicious_functions = ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory']
    for func in suspicious_functions:
        df[f'Uses_{func}'] = df['FunctionImports'].apply(lambda funcs: 1 if func in funcs else 0)

    df['IsDLL'] = df['Characteristics'].apply(lambda x: 1 if pd.notna(x) and x & 0x2000 else 0)
    df['IsExecutable'] = df['Characteristics'].apply(lambda x: 1 if pd.notna(x) and x & 0x0002 else 0)

    if 'TotalEntropy' not in df.columns:
        df['TotalEntropy'] = df['Sections'].apply(lambda x: np.mean([s.get('Entropy', 0) for s in eval(x)]) if isinstance(x, str) and pd.notna(x) else 0)

    df['HasMacros'] = df['Macros'].apply(lambda x: 0 if x == "No Macros stream found." else 1)

    drop_columns = ['Imports', 'Exports', 'Sections', 'Macros', 'FunctionImports']
    df.drop(columns=drop_columns, inplace=True)

    return df


def prepare_data_for_h2o(df):
    le = LabelEncoder()
    categorical_columns = df.select_dtypes(include=['object']).columns
    for col in categorical_columns:
        df[col] = le.fit_transform(df[col].astype(str))

    imputer = SimpleImputer(strategy='mean')
    df_imputed = pd.DataFrame(imputer.fit_transform(df), columns=df.columns)

    scaler = StandardScaler()
    df_imputed[df_imputed.columns] = scaler.fit_transform(df_imputed[df_imputed.columns])

    selector = VarianceThreshold()
    df_selected = pd.DataFrame(selector.fit_transform(df_imputed), columns=df_imputed.columns[selector.get_support()])

    return df_selected

df = load_and_preprocess_data(DATA_FILE)
df = engineer_features(df)
df = prepare_data_for_h2o(df)

train_df, valid_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df['Label'])

train_h2o = h2o.H2OFrame(train_df)
valid_h2o = h2o.H2OFrame(valid_df)

y_col = 'Label'
X_cols = [col for col in train_h2o.columns if col != y_col]

aml = H2OAutoML(
    max_models=200,
    seed=42,
    balance_classes=True,
    max_runtime_secs=36000,
    stopping_metric="AUC",
    sort_metric="AUC",
    exclude_algos=[],
    project_name="MalwareDetection",
    max_runtime_secs_per_model=1200,
    nfolds=10,
    include_algos=["GLM", "DRF", "XGBoost", "StackedEnsemble", "GBM", "DeepLearning", "NaiveBayes", "StackedEnsemble"],
    stopping_rounds=5,
    max_runtime_secs_per_algorithm=3600,
)


aml.train(x=X_cols, y=y_col, training_frame=train_h2o, validation_frame=valid_h2o)

lb = aml.leaderboard
print(lb.head(rows=10))

best_model = aml.leader
print(f"\nBest Model: {best_model}")

model_path = h2o.save_model(model=best_model, path="C:/Users/26dwi/ENTRYL/src-ai/ai-training/models", force=True)
print(f"\nModel saved to: {model_path}")

valid_h2o_pred = best_model.predict(valid_h2o)
valid_pred = valid_h2o_pred.as_data_frame()['p1']  # Probability of the positive class
valid_true = valid_df[y_col].values

fpr, tpr, _ = roc_curve(valid_true, valid_pred)
roc_auc = auc(fpr, tpr)

plt.figure(figsize=(10, 6))
plt.plot(fpr, tpr, color='blue', lw=2, label='ROC curve (area = {:.2f})'.format(roc_auc))
plt.plot([0, 1], [0, 1], color='red', lw=2, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic (ROC) Curve')
plt.legend(loc='lower right')
plt.grid()
plt.savefig('C:/Users/26dwi/ENTRYL/src-ai/ai-training/models/roc_curve.png')
plt.show()

precision, recall, _ = precision_recall_curve(valid_true, valid_pred)
plt.figure(figsize=(10, 6))
plt.plot(recall, precision, color='green', lw=2)
plt.xlabel('Recall')
plt.ylabel('Precision')
plt.title('Precision-Recall Curve')
plt.grid()
plt.savefig('C:/Users/26dwi/ENTRYL/src-ai/ai-training/models/precision_recall_curve.png')
plt.show()

conf_matrix = confusion_matrix(valid_true, (valid_pred > 0.5).astype(int))
plt.figure(figsize=(8, 6))
sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues', cbar=False,
            xticklabels=['Non-Malware', 'Malware'],
            yticklabels=['Non-Malware', 'Malware'])
plt.xlabel('Predicted Label')
plt.ylabel('True Label')
plt.title('Confusion Matrix')
plt.savefig('C:/Users/26dwi/ENTRYL/src-ai/ai-training/models/confusion_matrix.png')
plt.show()

shap_values = shap.TreeExplainer(best_model).shap_values(valid_h2o)
shap.summary_plot(shap_values, valid_h2o, plot_type="bar", show=False)
plt.savefig('C:/Users/26dwi/ENTRYL/src-ai/ai-training/models/shap_summary_plot.png')
plt.show()
