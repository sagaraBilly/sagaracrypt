# Sagara Crypt (Data Lock Safety and Cryptography)

A simple code that can encrypt, decrypt, and file hashing.<br>
created by: sagarabilly

## Features

- Data Encryption and Decryption
- Data File Checker and Hashing 
- Secure File Deletion
- File Compression and Decompression

## Setup
you need python to run the program and some library dependencies.  

1. Clone this repository:<br>
```git clone sagaraBilly/sagaracrypt```

2. Change directory to the folder that you just cloned<br>

3. See the contents:<br>
```python -m sagaracrypt --help```

## Use Case Example

1. Encryption<br>
```python sagaracrypt.py --encrypt input.txt encrypted_output.txt myencryptionkey123```

2. Decryption<br>
```python sagaracrypt.py --decrypt encrypted_output.txt decrypted_output.txt myencryptionkey12i3```

3. Compression<br>
```python sagaracrypt.py --compress input.txt compressed_output.zip```

4. Decompression<br>
```python sagaracrypt.py --decompress compressed_output.zip decompressed_folder```

5. Hashing<br>
```python sagaracrypt.py --hash sha256 input.txt```<br>
```python sagaracrypt.py --hash sha1 input.txt```<br>
```python sagaracrypt.py --hash md5 input.txt```

6. Secure Deletion<br>
```python sagaracrypt.py --secure-delete input.txt```
