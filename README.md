# Sagara Crypt (Data Lock Safety and Cryptography)

A simple code that can encrypt, decrypt, and hash a file.
by: sagarabilly

## Features

- Data Encryption and Decryption
- Data File Checker and Hashing 
- Secure File Deletion
- File Compression and Decompression

## Setup
you need python to run the program and some library dependencies.  

1. Clone this repository:
git clone sagaraBilly/sagaracrypt

2. Change directory to the folder that you just cloned

3. See the contents:
python -m sagaracrypt --help

## Use Case Example

1. Encryption
```python sagaracrypt.py --encrypt input.txt encrypted_output.txt myencryptionkey123```

2. Decryption
```python sagaracrypt.py --decrypt encrypted_output.txt decrypted_output.txt myencryptionkey12i3```

3. Compression
```python sagaracrypt.py --compress input.txt compressed_output.zip```

4. Decompression
```python sagaracrypt.py --decompress compressed_output.zip decompressed_folder```

5. Hashing
```python sagaracrypt.py --hash sha256 input.txt```
```python sagaracrypt.py --hash sha1 input.txt```
```python sagaracrypt.py --hash md5 input.txt```

6. Secure Deletion
```python sagaracrypt.py --secure-delete input.txt```
