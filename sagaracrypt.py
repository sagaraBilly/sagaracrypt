import os
import argparse
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def encrypt_file(input_file, output_file, key):
    """Encrypt the contents of the input file and write to the output file."""
    #Initialization
    iv = os.urandom(16) #random initialization vector 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'r', encoding='utf-8') as f:
        data = f.read()

    # Encode
    data_bytes = data.encode('utf-8')

    # Padding to fit block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data_bytes) + padder.finalize()

    # Encryption
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(iv + encrypted_data)  # Prepend IV to the encrypted data

def decrypt_file(input_file, output_file, key):
    """Decrypt the contents of the input file and write to the output file."""
    with open(input_file, 'rb') as f:
        iv = f.read(16)  # Read the IV
        encrypted_data = f.read()
    
    #Initialization
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decryption
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpadding the block data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    decoded_data = data.decode('utf-8')

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(decoded_data)

def cal_sha256(file_path):
    sha256_hash = hashlib.sha256()
    
    try:
        # Open in binary mode
        with open(file_path, "rb") as f:
            # Read the file in chunks of 4K bytes
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        # Return hexadecimal representation
        return sha256_hash.hexdigest()
    
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def save_hash_result(input_file, hash_result):
    file_name_without_extension = os.path.splitext(input_file)[0]
    save_path = f"{file_name_without_extension}_hashresult.txt"
    
    # Save hash to the generated file
    with open(save_path, 'w') as f:
        f.write(hash_result)
    print(f"Hash result saved to '{save_path}'")

def main():
    parser = argparse.ArgumentParser(description='''##SAGARACRYPT##. Encrypt or decrypt or save a 256Hash value a file. Encryption is done with AES-128 Module. PLEASE DON'T USE THIS CODE IF YOU ARE NOT SURE AND DON'T WANT YOUR TEXT DATA TO BE ENCRYPTED! MAKE SURE YOU REMEMBER THE KEY AND DON'T MISS TYPE IT! YOU HAVE BEEN WARNED!''')
    
    parser.add_argument('--encrypt', action='store_true', help='Encrypt the input file.')
    parser.add_argument('--decrypt', action='store_true', help='Decrypt the input file.') 
    parser.add_argument('--hash256', action='store_true', help='256SHA File Hashing')
    parser.add_argument('input_file', help='Path to the input file.')
    parser.add_argument('output_file', help='Path to the output file.', nargs='?')
    parser.add_argument('key', help='Encryption key as a simple string (16 characters for AES-128).', nargs='?')
    
    args = parser.parse_args()
    
    if args.encrypt or args.decrypt:
        # Key setup
        if len(args.key) != 16:
            parser.error('Key must be exactly 16 characters long for AES-128.')
        key = args.key.encode('utf-8')

        # Confirmation prompt
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
    
    if args.hash256:
        hash_result = cal_sha256(args.input_file)
        
        if hash_result:
            print(f"SHA-256 Hash of the file '{args.input_file}': {hash_result}")
            save_hash_result(args.input_file, hash_result)      

if __name__ == "__main__":
    main()
