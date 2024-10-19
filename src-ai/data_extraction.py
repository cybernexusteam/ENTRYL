import os
import hashlib
import pefile
import olefile
import json
import csv
import struct
import math
from collections import Counter

# Define directories (PLEASE CHANGE TO YOUR OWN DIRECTORY)
BENIGN_DIR = 'C:/Users/26dwi/ENTRYL/src-ai/ai-training/data/benign'
MALICIOUS_DIR = 'C:/Users/26dwi/ENTRYL/src-ai/ai-training/data/malware'
OUTPUT_DIR = 'C:/Users/26dwi/ENTRYL/src-ai/ai-training/extracted'

def hash_file(file_path):
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
    except Exception as e:
        print(f"Error reading file for hashing: {file_path}, Error: {e}")
        return None
    return sha256_hash.hexdigest()

def check_file_type(file_path):
    """Check if the file is NE, PE, or OLE by examining the header."""
    try:
        with open(file_path, "rb") as f:
            mz_header = f.read(64)
            if mz_header[:2] == b'MZ':
                ne_pe_offset = struct.unpack_from('<I', mz_header, 0x3C)[0]
                f.seek(ne_pe_offset)
                ne_pe_header = f.read(2)
                if ne_pe_header == b'PE':
                    return 'PE'
                elif ne_pe_header == b'NE':
                    return 'NE'
            elif olefile.isOleFile(file_path):
                return 'OLE'
    except Exception as e:
        print(f"Error checking file type for {file_path}: {e}")
    return 'UNKNOWN'

def calculate_entropy(data):
    """Calculate the entropy of given data."""
    if not data or len(data) == 0:
        return 0
    entropy = 0
    for x in Counter(data).values():
        p_x = x / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def extract_pe_features(file_path):
    """Extract static features from a PE file."""
    features = {}
    try:
        pe = pefile.PE(file_path)
        
        features['FileSize'] = os.path.getsize(file_path)
        features['SHA256'] = hash_file(file_path) or 'Error computing hash'
        
        features['Machine'] = pe.FILE_HEADER.Machine
        features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
        features['TimeDateStamp'] = pe.FILE_HEADER.TimeDateStamp
        features['PointerToSymbolTable'] = pe.FILE_HEADER.PointerToSymbolTable
        features['Characteristics'] = pe.FILE_HEADER.Characteristics
        
        features['ImageBase'] = getattr(pe.OPTIONAL_HEADER, 'ImageBase', 'N/A')
        features['SizeOfImage'] = getattr(pe.OPTIONAL_HEADER, 'SizeOfImage', 'N/A')
        features['Subsystem'] = getattr(pe.OPTIONAL_HEADER, 'Subsystem', 'N/A')
        features['DllCharacteristics'] = getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 'N/A')
        
        features['Sections'] = []
        for section in pe.sections:
            try:
                section_info = {
                    'Name': section.Name.decode('latin-1', errors='replace').strip(),
                    'VirtualAddress': section.VirtualAddress,
                    'Misc_VirtualSize': section.Misc_VirtualSize,
                    'SizeOfRawData': section.SizeOfRawData,
                    'PointerToRawData': section.PointerToRawData,
                    'Entropy': calculate_entropy(section.get_data()) if section.SizeOfRawData > 0 else 0
                }
                features['Sections'].append(section_info)
            except Exception as e:
                print(f"Error extracting section from {file_path}: {e}")
                continue
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            features['Imports'] = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_info = {
                        'DLL': entry.dll.decode('latin-1', errors='replace'),
                        'Functions': [imp.name.decode('latin-1', errors='replace') if imp.name else str(imp.ordinal) for imp in entry.imports]
                    }
                    features['Imports'].append(dll_info)
                except Exception as e:
                    print(f"Error extracting imports from {file_path}: {e}")
                    continue
        
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            features['Exports'] = []
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    features['Exports'].append(exp.name.decode('latin-1', errors='replace') if exp.name else "N/A")
                except Exception as e:
                    print(f"Error extracting exports from {file_path}: {e}")
                    continue
        
        features['TotalEntropy'] = calculate_entropy(pe.__data__)
        
    except pefile.PEFormatError as e:
        print(f"PEFormatError in file {file_path}: {e}")
        features['Error'] = 'Invalid PE file'
    except Exception as e:
        print(f"Error processing PE file {file_path}: {e}")
        features['Error'] = str(e)
    
    return features

def extract_ne_features(file_path):
    """Extract basic features from an NE (New Executable) file."""
    features = {}
    try:
        with open(file_path, "rb") as f:
            features['FileSize'] = os.path.getsize(file_path)
            features['SHA256'] = hash_file(file_path) or 'Error computing hash'
            
            f.seek(0x3C)
            ne_header_offset = struct.unpack('<I', f.read(4))[0]
            f.seek(ne_header_offset + 2)

            features['LinkerVersion'] = struct.unpack('<B', f.read(1))[0]
            features['LinkerRevision'] = struct.unpack('<B', f.read(1))[0]
            features['EntryTableOffset'] = struct.unpack('<H', f.read(2))[0]
            features['EntryTableLength'] = struct.unpack('<H', f.read(2))[0]
            features['FileFlags'] = struct.unpack('<H', f.read(2))[0]
            
            f.seek(0, 0)
            features['TotalEntropy'] = calculate_entropy(f.read())

    except Exception as e:
        print(f"Error extracting NE features from {file_path}: {e}")
        features['Error'] = str(e)
    
    return features

def extract_ole_features(file_path):
    """Extract static features from an OLE file."""
    features = {}
    
    try:
        ole = olefile.OleFileIO(file_path)
        
        features['FileSize'] = os.path.getsize(file_path)
        features['SHA256'] = hash_file(file_path) or 'Error computing hash'
        
        features['Streams'] = ole.listdir()
        
        metadata_streams = ["\x05SummaryInformation", "\x05DocumentSummaryInformation"]
        metadata = {}
        
        for stream in metadata_streams:
            if ole.exists(stream):
                try:
                    stream_data = ole.openstream(stream).read()
                    metadata[stream] = stream_data.decode('utf-16', errors='replace')
                except Exception as e:
                    metadata[stream] = f"Error reading stream: {str(e)}"
        
        features['Metadata'] = metadata

        if ole.exists('Macros'):
            try:
                macro_stream = ole.openstream('Macros')
                features['Macros'] = macro_stream.read().decode('utf-8', errors='replace')
            except Exception as e:
                features['Macros'] = f"Error reading macros: {str(e)}"
        else:
            features['Macros'] = "No Macros stream found."
        
        features['TotalEntropy'] = calculate_entropy(open(file_path, 'rb').read())
        
    except Exception as e:
        print(f"Error extracting OLE features from {file_path}: {e}")
        features['Error'] = str(e)
    
    return features

def process_directory(directory, label):
    """Process all files in a directory and extract features."""
    extracted_data = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Processing file: {file_path}")
            
            file_type = check_file_type(file_path)
            
            if file_type == 'PE':
                features = extract_pe_features(file_path)
            elif file_type == 'NE':
                features = extract_ne_features(file_path)
            elif file_type == 'OLE':
                features = extract_ole_features(file_path)
            else:
                print(f"Unsupported file type: {file_path}")
                continue
                
            features['Label'] = label
            features['FileType'] = file_type
            extracted_data.append(features)
    
    return extracted_data

def save_to_json(data, filename):
    """Save extracted data to a JSON file."""
    try:
        with open(os.path.join(OUTPUT_DIR, filename), 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error saving to JSON file {filename}: {e}")

def save_to_csv(data, filename):
    """Save extracted data to a CSV file."""
    all_fieldnames = set()
    for item in data:
        all_fieldnames.update(item.keys())

    all_fieldnames = list(all_fieldnames)

    try:
        with open(os.path.join(OUTPUT_DIR, filename), 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=all_fieldnames)
            writer.writeheader()
            for row in data:
                filled_row = {field: row.get(field, 'N/A') for field in all_fieldnames}
                writer.writerow(filled_row)
    except Exception as e:
        print(f"Error saving to CSV file {filename}: {e}")

# Main execution
if __name__ == '__main__':
    print("Extracting features from benign files...")
    benign_data = process_directory(BENIGN_DIR, label='benign')
    
    print("Extracting features from malicious files...")
    malicious_data = process_directory(MALICIOUS_DIR, label='malicious')
    
    all_data = benign_data + malicious_data
    
    print("Saving data to JSON and CSV...")
    save_to_json(all_data, 'extracted_data4.json')
    save_to_csv(all_data, 'extracted_data4.csv')
    
    print("Feature extraction completed successfully.")
