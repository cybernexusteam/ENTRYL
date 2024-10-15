import os
import json
import hashlib
import pefile
import olefile
import csv
import traceback
import numpy as np
from tkinter import filedialog, Tk, messagebox, scrolledtext
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

def select_directory():
    """Prompt the user to select a directory."""
    root = Tk()
    root.withdraw()  # Hide the root window
    selected_directory = filedialog.askdirectory(title="Select a Directory to Scan")
    root.destroy()
    
    if not selected_directory:
        print("No directory selected, exiting.")
        exit(1)
    
    return selected_directory

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

def save_to_json(data):
    """Save extracted data to a JSON file."""
    try:
        with open(EXTRACTED_DATA_PATH, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Extracted data saved to {EXTRACTED_DATA_PATH}")
    except Exception as e:
        print(f"Error saving data to JSON: {str(e)}")
        traceback.print_exc()

def save_to_csv(data):
    """Save extracted data to a CSV file."""
    try:
        all_fieldnames = set()
        for item in data:
            all_fieldnames.update(item.keys())

        all_fieldnames = list(all_fieldnames)

        with open(os.path.join(TEMP_DIR, 'extracted_data.csv'), 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=all_fieldnames)
            writer.writeheader()
            for row in data:
                filled_row = {field: row.get(field, 'N/A') for field in all_fieldnames}
                writer.writerow(filled_row)
        print(f"Extracted data saved to {os.path.join(TEMP_DIR, 'extracted_data.csv')}")
    except Exception as e:
        print(f"Error saving data to CSV: {str(e)}")
        traceback.print_exc()

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
            print("Saving extracted data to JSON and CSV...")
            save_to_json(extracted_data)
            save_to_csv(extracted_data)
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
        show_error_popup(f"Error loading H2O model: {str(e)}")
        exit(1)

def run_model_on_extracted_data(model):
    """Run the H2O model on the extracted data."""
    try:
        with open(EXTRACTED_DATA_PATH, 'r') as data_file:
            extracted_data = json.load(data_file)

        # Flatten the extracted data into feature vectors
        feature_vectors = [flatten_features(item) for item in extracted_data]

        # Convert feature vectors into an H2OFrame
        df_h2o = h2o.H2OFrame(feature_vectors)

        # Make predictions using the H2O model
        predictions = model.predict(df_h2o)

        # Attach predictions to each extracted feature
        for i, item in enumerate(extracted_data):
            item['prediction'] = predictions[i, 0]  # Get the predicted class

        return extracted_data
    except Exception as e:
        show_error_popup(f"Error running model on extracted data: {str(e)}")
        traceback.print_exc()

def save_results(results):
    """Save the results of the predictions to a global location."""
    try:
        with open(RESULTS_PATH, 'w') as output_file:
            json.dump(results, output_file, indent=4)
        print(f"Results saved to: {RESULTS_PATH}")
    except Exception as e:
        show_error_popup(f"Error saving results: {str(e)}")
        exit(1)

def show_error_popup(error_message):
    """Show a popup window displaying the error message."""
    root = Tk()
    root.title("Error")
    root.geometry("600x400")
    
    # Create a scrolled text box to display the error message
    text_box = scrolledtext.ScrolledText(root, wrap="word")
    text_box.pack(expand=True, fill="both")
    text_box.insert("1.0", error_message)

    # Create an "OK" button to close the window
    ok_button = messagebox.showinfo("Error", error_message)
    root.mainloop()

def main():
    """Main function to run the complete checking process."""
    try:
        # Step 1: Prompt for directory
        selected_directory = select_directory()
        print(f"Selected directory: {selected_directory}")

        # Step 2: Run extraction script
        print("Running the extraction script...")
        run_extraction_script(selected_directory)

        # Step 3: Load the pre-trained H2O model
        model_path = "C:/Users/26dwi/ENTRYL/src-ai/ai-training/models/StackedEnsemble_AllModels_1_AutoML_1_20241014_193144"  # Update this to your model's path
        print("Loading the machine learning model...")
        model = load_h2o_model(model_path)

        # Step 4: Run the model on the extracted data
        print("Running the model on the extracted data...")
        results = run_model_on_extracted_data(model)

        # Step 5: Save the results
        print("Saving the results...")
        save_results(results)

        print("Process completed.")
    except Exception as e:
        show_error_popup(f"Error in main process: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    main()