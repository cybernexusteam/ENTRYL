import os
import json
import hashlib
import pefile
import olefile
import csv
import traceback
import numpy as np
import h2o  # Import H2O library

# Initialize H2O Cluster
h2o.init()

# Define global paths for temporary storage inside the ENTRYL folder
TEMP_DIR = os.path.join(os.getenv('PROGRAMDATA'), 'ENTRYL', 'temp')  # Temporary folder path

# Ensure the temp directory exists
os.makedirs(TEMP_DIR, exist_ok=True)  # Create the temp directory if it doesn't exist
print(f"Temporary directory created at: {TEMP_DIR}")

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

# Clear any existing files in the temp directory
clear_temp_directory()

# Paths for extracted data and results within the temp directory
EXTRACTED_DATA_PATH = os.path.join(TEMP_DIR, 'extracted_data.json')
RESULTS_PATH = os.path.join(TEMP_DIR, 'results.json')

def hash_file(file_path):
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def extract_pe_features(file_path):
    """Extract static features from a PE file."""
    features = {}
    
    try:
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
        
        # Sections info
        features['Sections'] = []
        for section in pe.sections:
            section_info = {
                'Name': section.Name.decode('latin-1', errors='replace').strip(),
                'VirtualAddress': section.VirtualAddress,
                'Misc_VirtualSize': section.Misc_VirtualSize,
                'SizeOfRawData': section.SizeOfRawData,
                'PointerToRawData': section.PointerToRawData
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
                
    except pefile.PEFormatError:
        features['Error'] = 'Invalid PE file'
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
            ole.close()
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
    
    # Look for executable and OLE files
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
        
        # Save the extracted data
        if extracted_data:
            print("Saving extracted data to JSON...")
            save_to_json(extracted_data)
            print("Feature extraction completed successfully.")
        else:
            print("No relevant files found for extraction.")
    except Exception as e:
        print(f"Error during extraction script: {str(e)}")
        traceback.print_exc()

def load_h2o_model(model_path):
    """Load the trained H2O model."""
    try:
        model = h2o.load_model(model_path)
        print("H2O model loaded successfully.")
        return model
    except Exception as e:
        print(f"Error loading H2O model: {str(e)}")
        exit(1)

def run_model_on_extracted_data(model):
    """Run the H2O model on the extracted data."""
    try:
        with open(EXTRACTED_DATA_PATH, 'r') as data_file:
            extracted_data = json.load(data_file)

        # Flatten the extracted data into feature vectors
        flattened_data = [flatten_features(item) for item in extracted_data]
        
        # Convert to H2OFrame for prediction
        h2o_frame = h2o.H2OFrame(flattened_data)
        predictions = model.predict(h2o_frame)
        
        # Save predictions to a JSON file
        results = []
        for idx, item in enumerate(extracted_data):
            prediction = {
                'SHA256': item['SHA256'],
                'Prediction': predictions[idx, 0],
                'Maliciousness': "Malicious" if predictions[idx, 0] > 0.5 else "Benign"  # Assuming binary classification
            }
            results.append(prediction)

        # Write results to file
        with open(RESULTS_PATH, 'w') as result_file:
            json.dump(results, result_file, indent=2)
        
        print("Predictions have been written to the results file.")
        
    except Exception as e:
        print(f"Error during model prediction: {str(e)}")
        traceback.print_exc()

def save_to_json(data):
    """Save extracted data to a JSON file."""
    with open(EXTRACTED_DATA_PATH, 'w') as json_file:
        json.dump(data, json_file, indent=2)

def main():
    """Main function to orchestrate feature extraction and model prediction."""
    try:
        # Specify the directory to process
        directory_to_process = os.getenv('DIRECTORY_TO_PROCESS', './sample_files')
        run_extraction_script(directory_to_process)
        
        # Load the H2O model
        model_path = os.getenv('MODEL_PATH', './model')
        model = load_h2o_model(model_path)
        
        # Run model on extracted data
        run_model_on_extracted_data(model)
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    main()