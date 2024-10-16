import os
import hashlib
import pefile
import olefile
import json
import csv
import struct

# Define directories (PLEASE CHANGE TO YOUR OWN DIRECTORY)
BENIGN_DIR = 'C:/Users/26dwi/ENTRYL/src-ai/ai-training/data/benign'
MALICIOUS_DIR = 'C:/Users/26dwi/ENTRYL/src-ai/ai-training/data/malware'
OUTPUT_DIR = 'C:/Users/26dwi/ENTRYL/src-ai/ai-training/extracted'

def hash_file(file_path):
    """Calculates the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_file_type(file_path):
    """Check if the file is NE, PE, or OLE by examining the header."""
    with open(file_path, "rb") as f:
        # Read the first 64 bytes to check for MZ, PE, NE, or OLE signature
        mz_header = f.read(64)

        # Check if the file starts with "MZ"
        if mz_header[:2] == b'MZ':
            # Offset to the NE/PE header is located at byte 0x3C (60 in decimal)
            ne_pe_offset = struct.unpack_from('<I', mz_header, 0x3C)[0]
            f.seek(ne_pe_offset)
            ne_pe_header = f.read(2)

            if ne_pe_header == b'PE':
                return 'PE'
            elif ne_pe_header == b'NE':
                return 'NE'
            else:
                return 'UNKNOWN'
        else:
            return 'UNKNOWN'

def is_ole_file(file_path):
    """Check if a file is a valid OLE2 structured storage file."""
    try:
        return olefile.isOleFile(file_path)
    except Exception as e:
        return False

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
    
    return features

def extract_ne_features(file_path):
    """Extract basic features from an NE (New Executable) file."""
    features = {}
    try:
        with open(file_path, "rb") as f:
            # Basic file information
            features['FileSize'] = os.path.getsize(file_path)
            features['SHA256'] = hash_file(file_path)
            
            # Read NE header (at offset 0x3C + 2 bytes for 'NE' signature)
            f.seek(0x3C)
            ne_header_offset = struct.unpack('<I', f.read(4))[0]
            f.seek(ne_header_offset + 2)  # Skip past 'NE' signature

            # Read some key fields from NE header
            features['LinkerVersion'] = struct.unpack('<B', f.read(1))[0]
            features['LinkerRevision'] = struct.unpack('<B', f.read(1))[0]
            features['EntryTableOffset'] = struct.unpack('<H', f.read(2))[0]
            features['EntryTableLength'] = struct.unpack('<H', f.read(2))[0]
            features['FileFlags'] = struct.unpack('<H', f.read(2))[0]

    except Exception as e:
        features['Error'] = str(e)
    
    return features

def extract_ole_features(file_path):
    """Extract static features from an OLE file."""
    features = {}
    
    if not is_ole_file(file_path):
        features['Error'] = 'Not a valid OLE file'
        return features
    
    try:
        ole = olefile.OleFileIO(file_path)
        
        # Basic file information
        features['FileSize'] = os.path.getsize(file_path)
        features['SHA256'] = hash_file(file_path)
        
        # List all streams and storages in the OLE file
        features['Streams'] = ole.listdir()
        
        # Extract metadata if the OLE file has document properties
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

        # Extract macros if the 'Macros' stream is present
        if ole.exists('Macros'):  # Check if 'Macros' stream exists
            try:
                macro_stream = ole.openstream('Macros')
                features['Macros'] = macro_stream.read().decode('utf-8', errors='replace')
            except Exception as e:
                features['Macros'] = f"Error reading macros: {str(e)}"
        else:
            features['Macros'] = "No Macros stream found."
        
    except Exception as e:
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
            elif is_ole_file(file_path):
                features = extract_ole_features(file_path)
            else:
                print(f"Unsupported file type: {file_path}")
                continue
                
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

    # Write the CSV file with UTF-8 encoding
    with open(os.path.join(OUTPUT_DIR, filename), 'w', newline='', encoding='utf-8') as csvfile:
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
    save_to_json(all_data, 'extracted_data2.json')
    save_to_csv(all_data, 'extracted_data2.csv')
    
    print("Feature extraction completed successfully.")