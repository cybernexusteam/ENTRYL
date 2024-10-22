import os
import json
import hashlib
import pefile
import olefile
import traceback
import math
import h2o  # Import H2O library
from collections import Counter
import tkinter as tk
from tkinter import filedialog

# Initialize H2O Cluster
h2o.init()

# Define global paths for temporary storage inside the ENTRYL folder
TEMP_DIR = os.path.join(os.getenv('PROGRAMDATA'), 'ENTRYL', 'temp')  # Temporary folder path

# Ensure the temp directory exists
os.makedirs(TEMP_DIR, exist_ok=True)
print(f"Temporary directory created at: {TEMP_DIR}")

# Paths for extracted data and results within the temp directory
EXTRACTED_DATA_PATH = os.path.join(TEMP_DIR, 'extracted_data.json')
RESULTS_PATH = os.path.join(TEMP_DIR, 'results.json')

def clear_temp_directory():
    """Delete all files in the temporary directory."""
    try:
        for filename in os.listdir(TEMP_DIR):
            file_path = os.path.join(TEMP_DIR, filename)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    print(f"Deleted file: {file_path}")
                elif os.path.isdir(file_path):
                    os.rmdir(file_path)  # Remove empty directories, if any
                    print(f"Deleted directory: {file_path}")
            except Exception as e:
                print(f"Error deleting {file_path}: {str(e)}")
    except Exception as e:
        print(f"Error clearing temp directory: {str(e)}")

clear_temp_directory()

def prompt_directory():
    root = tk.Tk()
    root.withdraw()
    directory_to_process = filedialog.askdirectory(title="Please select the directory to process")
    return directory_to_process

def hash_file(file_path):
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def calculate_entropy(data):
    """Calculate the entropy of given data."""
    if not data or len(data) == 0:
        return 0
    entropy = 0
    for x in Counter(data).values():
        p_x = x / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

import os
import pefile
import traceback

def extract_pe_features(file_path):
    """Extract static features from a PE file."""
    features = {}
    
    try:
        # Ensure the file path is correctly formatted for the OS
        file_path = os.path.normpath(file_path)

        # Check if the file exists
        if not os.path.isfile(file_path):
            features['Error'] = f'File does not exist: {file_path}'
            return features

        pe = pefile.PE(file_path)
        
        # Basic file information
        features['FileSize'] = os.path.getsize(file_path)
        features['SHA256'] = hash_file(file_path)
        
        # PE Header info
        features['Machine'] = pe.FILE_HEADER.Machine
        features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
        features['TimeDateStamp'] = pe.FILE_HEADER.TimeDateStamp
        features['PointerToSymbolTable'] = pe.FILE_HEADER.PointerToSymbolTable
        features['Characteristics'] = pe.FILE_HEADER.Characteristics
        
        # Optional Header
        features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        
        # Sections info with entropy
        features['Sections'] = []
        for section in pe.sections:
            section_info = {
                'Name': section.Name.decode('latin-1', errors='replace').strip(),
                'VirtualAddress': section.VirtualAddress,
                'Misc_VirtualSize': section.Misc_VirtualSize,
                'SizeOfRawData': section.SizeOfRawData,
                'PointerToRawData': section.PointerToRawData,
                'Entropy': calculate_entropy(section.get_data()) if section.SizeOfRawData > 0 else 0
            }
            features['Sections'].append(section_info)
        
        # Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            features['Imports'] = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_info = {
                    'DLL': entry.dll.decode('latin-1', errors='replace'),
                    'Functions': [imp.name.decode('latin-1', errors='replace') if imp.name else str(imp.ordinal) for imp in entry.imports]
                }
                features['Imports'].append(dll_info)
        
        # Exported Functions
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            features['Exports'] = []
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                features['Exports'].append(exp.name.decode('latin-1', errors='replace') if exp.name else "N/A")
        
        # Total entropy of the PE file
        features['TotalEntropy'] = calculate_entropy(pe.__data__)
                
    except pefile.PEFormatError:
        features['Error'] = 'Invalid PE file format'
    except Exception as e:
        print(f"Error extracting PE features from {file_path}: {str(e)}")
        traceback.print_exc()
        features['Error'] = 'Failed to extract PE features'
    
    return features


def extract_ole_features(file_path):
    """Extract basic features from an OLE file."""
    features = {
        'FileSize': os.path.getsize(file_path),
        'SHA256': hash_file(file_path),
    }
    
    try:
        if olefile.isOleFile(file_path):
            ole = olefile.OleFileIO(file_path)
            features['Streams'] = ole.listdir()

            metadata_streams = ["\\x05SummaryInformation", "\\x05DocumentSummaryInformation"]
            metadata = {}
            
            for stream in metadata_streams:
                if ole.exists(stream):
                    try:
                        stream_data = ole.openstream(stream).read()
                        metadata[stream] = stream_data.decode('utf-16', errors='replace')
                    except Exception as e:
                        metadata[stream] = f"Error reading stream: {str(e)}"
            
            features['Metadata'] = metadata
            
            ole.close()

            # Total entropy of the OLE file
            with open(file_path, 'rb') as f:
                features['TotalEntropy'] = calculate_entropy(f.read())
        else:
            features['Error'] = 'Not a valid OLE file'
    except Exception as e:
        print(f"Error processing OLE file {file_path}: {str(e)}")
        traceback.print_exc()
        features['Error'] = f"Error processing OLE file"
    
    return features

def process_directory(directory):
    """Process all relevant files in a directory and extract features."""
    extracted_data = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                if file.endswith('.exe'):
                    print(f"Processing PE file: {file_path}")
                    features = extract_pe_features(file_path)
                    if 'Error' not in features:
                        extracted_data.append(features)
                elif file.endswith('.ole'):
                    print(f"Processing OLE file: {file_path}")
                    features = extract_ole_features(file_path)
                    if 'Error' not in features:
                        extracted_data.append(features)
            except Exception as e:
                print(f"Error processing file {file_path}: {str(e)}")
                traceback.print_exc()

    return extracted_data


def flatten_features(item):
    """Flatten nested features in the extracted data."""
    flattened = {}

    # Copy scalar fields directly
    for key, value in item.items():
        if not isinstance(value, (list, dict)):
            flattened[key] = value

    # Flatten 'Sections': Count number of sections and sum of section sizes
    if 'Sections' in item:
        flattened['NumberOfSections'] = len(item['Sections'])
        flattened['TotalSectionSize'] = sum(sec.get('SizeOfRawData', 0) for sec in item['Sections'])
    else:
        flattened['NumberOfSections'] = 0
        flattened['TotalSectionSize'] = 0

    # Flatten 'Imports': Count number of DLLs and total number of imported functions
    if 'Imports' in item:
        flattened['NumberOfDLLs'] = len(item['Imports'])
        flattened['TotalImportedFunctions'] = sum(len(dll.get('Functions', [])) for dll in item['Imports'])
    else:
        flattened['NumberOfDLLs'] = 0
        flattened['TotalImportedFunctions'] = 0

    return flattened

def run_extraction_script(directory):
    """Perform extraction on the specified directory."""
    print(f"Processing directory: {directory}")
    try:
        extracted_data = process_directory(directory)
        
        flattened_data = [flatten_features(item) for item in extracted_data]

        # Save the extracted features to a JSON file
        with open(EXTRACTED_DATA_PATH, 'w') as f:
            json.dump(flattened_data, f)

        print(f"Extraction completed. Extracted data saved to: {EXTRACTED_DATA_PATH}")
        return flattened_data

    except Exception as e:
        print(f"Error during extraction: {str(e)}")
        traceback.print_exc()

def run_model_on_extracted_data(model_path):
    """Run the saved model on extracted data and handle missing columns."""
    try:
        # Load extracted data
        with open(EXTRACTED_DATA_PATH, 'r') as f:
            extracted_data = json.load(f)

        # Load H2O model
        model = h2o.load_model(model_path)

        # Convert extracted data to H2OFrame
        h2o_frame = h2o.H2OFrame(extracted_data)

        # Check if columns in extracted data match the training set columns
        model_columns = model._model_json['output']['names']
        extracted_columns = h2o_frame.names
        
        missing_columns = set(model_columns) - set(extracted_columns)
        for col in missing_columns:
            h2o_frame[col] = 0.0  # Add missing columns with default value 0.0

        # Predict using the model
        predictions = model.predict(h2o_frame)

        # Convert predictions to a list and map to 'Benign' or 'Malware'
        prediction_labels = []
        for pred in predictions.as_data_frame()['predict']:
            # Adjust the threshold as necessary, assuming 1 is malware and 0 is benign
            if pred == 1:
                prediction_labels.append("Malware")
            else:
                prediction_labels.append("Benign")

        # Combine extracted data with predictions
        results = []
        for i, item in enumerate(extracted_data):
            results.append({
                **item,  # Flattened features
                'Prediction': prediction_labels[i]
            })

        # Save predictions
        with open(RESULTS_PATH, 'w') as f:
            json.dump(results, f)

        print(f"Model predictions saved to: {RESULTS_PATH}")
    
    except Exception as e:
        print(f"Error during model prediction: {str(e)}")
        traceback.print_exc()


if __name__ == "__main__":
    # Ask user for the directory and perform extraction and prediction
    directory = prompt_directory()

    if directory:
        extracted_data = run_extraction_script(directory)

        model_path = "C:/Users/26dwi/ENTRYL/src-ai/ai-training/models/StackedEnsemble_BestOfFamily_1_AutoML_1_20241021_25258"  # Change to the actual path of your H2O model
        run_model_on_extracted_data(model_path)
    else:
        print("No directory selected. Exiting.")