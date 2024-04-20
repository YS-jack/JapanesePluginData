import sys
import os
import hashlib
from pathlib import Path
import zipfile

def strip_first_directory(path):
    """Strip the first directory from the path."""
    path_obj = Path(path)
    # Create a new path without the first part
    new_path = Path(*path_obj.parts[1:])
    return new_path

def hash_file(filepath):
    """Compute SHA256 hash of the specified file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def hash_directory(directory):
    """Compute SHA256 hash for all files in a directory collectively."""
    sha256_hash = hashlib.sha256()
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            with open(filepath, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def process_directory(root_directory, output_file):
    """Process each file and directory under the root directory."""
    with open(output_file, 'w') as out:
        for dirpath, dirnames, filenames in os.walk(root_directory):
            # Check for special 'char' directory
            if 'char' in dirnames:
                char_path = os.path.join(dirpath, 'char')
                hash_value = hash_directory(char_path)
                out.write(f"char|{hash_value}\n")
                dirnames.remove('char')  # Avoid processing 'char' directory again

            # Process regular files
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                hash_value = hash_file(filepath)
                no_first_dir = strip_first_directory(filepath)
                out.write(f"{no_first_dir}|{hash_value}\n")

def zip_char_img():
    zip_file_name = './repos/char.zip'
    folder_path = './repos/char'
    with zipfile.ZipFile(zip_file_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                # Create a proper path for each file to be stored in the zip
                file_path = os.path.join(root, file)
                # Adding file to zip
                zipf.write(file_path, os.path.relpath(file_path, os.path.dirname(folder_path)))

def main():
    directory_path = sys.argv[1]
    process_directory(directory_path, "hashList.txt")
    zip_char_img()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("use: python create_hash.py <folder to create hash of>")
        sys.exit(1)
    main()