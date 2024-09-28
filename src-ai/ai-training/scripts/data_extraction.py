import os
import hashlib
import pefile
import json
import csv
from collections import defaultdict

# Define directories PLEASE CHANGE TO YOUR OWN DIRECTORY (FOR TESTING PURPOSES ONLY)
BENIGN_DIR = '/home/pengu/NTRL/src-ai/ai-training/data/benign'
MALICIOUS_DIR = '/home/pengu/NTRL/src-ai/ai-training/data/malware'
OUTPUT_DIR = '/home/pengu/NTRL/src-ai/ai-training/extracted'

# Ensure output directory exists
if not os.path.exists(OUTPUT_DIR):
    print(f"NO OUTPUT DIRECTORY FOUND")

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
                # Decode using 'latin-1' to handle non-UTF-8 bytes
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
    
    return features


def process_directory(directory, label):
    """Process all files in a directory and extract features."""
    extracted_data = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Processing file: {file_path}")
            features = extract_pe_features(file_path)
            features['Label'] = label  # Assign benign or malicious label
            extracted_data.append(features)
    
    return extracted_data

def save_to_json(data, filename):
    """Save extracted data to a JSON file."""
    with open(os.path.join(OUTPUT_DIR, filename), 'w') as f:
        json.dump(data, f, indent=4)

def save_to_csv(data, filename):
    """Save extracted data to a CSV file."""
    # Collect all unique fieldnames (headers) from the data
    all_fieldnames = set()
    for item in data:
        all_fieldnames.update(item.keys())

    all_fieldnames = list(all_fieldnames)  # Convert to a list

    # Write the CSV file
    with open(os.path.join(OUTPUT_DIR, filename), 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=all_fieldnames)
        writer.writeheader()  # Write the header row
        for row in data:
            # Fill missing keys with 'N/A' before writing
            filled_row = {field: row.get(field, 'N/A') for field in all_fieldnames}
            writer.writerow(filled_row)


# Main execution
if __name__ == '__main__':
    # Extract features from benign and malicious files
    print("Extracting features from benign files...")
    benign_data = process_directory(BENIGN_DIR, label='benign')
    
    print("Extracting features from malicious files...")
    malicious_data = process_directory(MALICIOUS_DIR, label='malicious')
    
    # Combine both datasets
    all_data = benign_data + malicious_data
    
    # Save the extracted data
    print("Saving data to JSON and CSV...")
    save_to_json(all_data, 'extracted_data.json')
    save_to_csv(all_data, 'extracted_data.csv')
    
    print("Feature extraction completed successfully.")
