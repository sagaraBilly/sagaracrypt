import os
import argparse
import hashlib
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def encrypt_file(input_file, output_file, key):
    """Encrypt the contents of the input file and write to the output file."""
    
    # Initialization
    iv = os.urandom(16)  # random initialization vector 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f:
        data = f.read()

    # Padding to fit block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encryption
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(iv + encrypted_data)  # Prepend IV to the encrypted data

def decrypt_file(input_file, output_file, key):
    """Decrypt the contents of the input file and write to the output file."""
    with open(input_file, 'rb') as f:
        iv = f.read(16)  # Read the IV
        encrypted_data = f.read()
    
    # Initialization
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decryption
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpadding the block data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    with open(output_file, 'wb') as f:
        f.write(data)  # Write decrypted data in binary mode

def compress_file(input_file, output_file):
    """Compress the input file into a ZIP file."""
    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(input_file, os.path.basename(input_file))
    print(f"File compressed to '{output_file}'")

def decompress_file(input_file, output_file):
    """Decompress the ZIP file to the output file."""
    with zipfile.ZipFile(input_file, 'r') as zipf:
        zipf.extractall(os.path.dirname(output_file))
    print(f"File decompressed to '{output_file}'")

def cal_hash(file_path, algorithm):
    hash_obj = hashlib.new(algorithm)
    
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hash_obj.update(byte_block)
        return hash_obj.hexdigest()
    
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def save_hash_result(input_file, hash_result, algorithm):
    file_name_without_extension = os.path.splitext(input_file)[0]
    save_path = f"{file_name_without_extension}_{algorithm}_hashresult.txt"
    
    with open(save_path, 'w') as f:
        f.write(hash_result)
    print(f"Hash result saved to '{save_path}'")

def secure_delete(file_path):
    """Securely delete a file by overwriting it with random data."""
    if os.path.isfile(file_path):
        with open(file_path, "r+b") as f:
            length = os.path.getsize(file_path)
            f.write(os.urandom(length))  # Overwrite with random data
        os.remove(file_path)
        print(f"File '{file_path}' securely deleted.")
    else:
        print(f"File '{file_path}' does not exist.")

def main():
    parser = argparse.ArgumentParser(description='''##SAGARACRYPT##. Encrypt, decrypt, compress, decompress, or hash a file. 
    Encryption is done with AES-128 Module. Please ensure you remember the key!''')
    
    parser.add_argument('--encrypt', action='store_true', help='Encrypt the input file.')
    parser.add_argument('--decrypt', action='store_true', help='Decrypt the input file.') 
    parser.add_argument('--compress', action='store_true', help='Compress the input file into a ZIP file.')
    parser.add_argument('--decompress', action='store_true', help='Decompress the input ZIP file.')
    parser.add_argument('--hash', type=str, choices=['md5', 'sha1', 'sha256'], help='Hash the input file with the specified algorithm.')
    parser.add_argument('--secure-delete', action='store_true', help='Securely delete the specified file.')
    parser.add_argument('input_file', help='Path to the input file.')
    parser.add_argument('output_file', help='Path to the output file.', nargs='?')
    parser.add_argument('key', help='Encryption key as a simple string (16 characters for AES-128).', nargs='?')
    
    args = parser.parse_args()
    
    if args.encrypt or args.decrypt:
        if len(args.key) != 16:
            parser.error('Key must be exactly 16 characters long for AES-128.')
        key = args.key.encode('utf-8')

        action = "encrypt" if args.encrypt else "decrypt"
        confirmation = input(f"This will {action} the file '{args.input_file}'. Are you sure? (Y/N): ").strip().lower()
        
        if confirmation == 'y':
            if args.encrypt:
                encrypt_file(args.input_file, args.output_file, key)
                print(f"File encrypted and saved as '{args.output_file}'")
            elif args.decrypt:
                decrypt_file(args.input_file, args.output_file, key)
                print(f"File decrypted and saved as '{args.output_file}'")
        else:
            print("Operation canceled.")
    
    if args.compress:
        compress_file(args.input_file, args.output_file or f"{args.input_file}.zip")
    
    if args.decompress:
        decompress_file(args.input_file, args.output_file or f"{os.path.splitext(args.input_file)[0]}_decompressed")
    
    if args.hash:
        hash_result = cal_hash(args.input_file, args.hash)
        
        if hash_result:
            print(f"{args.hash.upper()} Hash of the file '{args.input_file}': {hash_result}")
            save_hash_result(args.input_file, hash_result, args.hash)
    
    if args.secure_delete:
        secure_delete(args.input_file)

if __name__ == "__main__":
    main()
