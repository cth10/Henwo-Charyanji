# Henwo Charyanji

A Python-based secure file handling utility with a modern GUI that implements strong encryption for both file protection and secure deletion. This tool combines encryption and secure deletion techniques to provide enhanced data protection.

## Core Operations

The program offers three primary operations:

### 1. Encrypt Only
- Files/folders are encrypted using AES-256-GCM
- Original files remain untouched
- Encrypted versions are saved with `.encrypted` extension
- Encryption credentials (password and salt) are provided and must be saved for later decryption

### 2. Encrypt and Delete
- Files/folders are first encrypted using AES-256-GCM
- Original files are securely deleted through:
  1. Encryption with a temporary key
  2. Overwriting with zeros
  3. Standard file system deletion
- Encrypted versions remain accessible with `.encrypted` extension
- Encryption credentials are provided for later decryption

### 3. Secure Destruction
- Files/folders are destroyed
- Process includes:
  1. Encryption with a temporary destruction key
  2. Overwriting with zeros
  3. Final deletion from the file system

## Key Features

* **Modern GUI**: Built with CustomTkinter for a clean, user-friendly interface
* **Drag & Drop**: Simple file selection interface
* **Batch Processing**: Handle multiple files simultaneously
* **Progress Tracking**: Real-time progress bar for all operations
* **Credential Management**: Secure handling and storage of encryption credentials
* **Large File Support**: Efficient handling of large files through chunked processing

## Technical Implementation

### Security Features
* **Encryption**: AES-256-GCM (Galois/Counter Mode)
* **Key Derivation**: PBKDF2-HMAC-SHA256 with 500,000 iterations
* **Chunk Processing**: 64MB chunks for efficient handling of large files
* **Secure Deletion**: Multi-step process including zero overwriting and pre-deletion encryption

### GUI Features
* Multiple file selection support
* Progress bar for operation tracking
* Status updates during operations
* Credential saving dialog with copy functionality

## Requirements

* Python 3.8+
* cryptography
* customtkinter
* tkinter

## Usage

### GUI Version
```bash
python secure_file_gui.py
```

### Main Operations

1. **Encrypt Files**
   - Select files using the file selector
   - Click "Encrypt Files"
   - Save the provided credentials securely

2. **Encrypt & Delete**
   - Select files
   - Click "Encrypt & Delete"
   - Save the credentials for future decryption
   - Original files are securely deleted

3. **Decrypt Files**
   - Select encrypted files (.encrypted extension)
   - Click "Decrypt Files"
   - Enter the password and salt when prompted
   - Files are restored to their original form

4. **Destroy Files**
   - Select files
   - Click "Destroy Files"
   - Confirm the destruction
   - Files are destroyed

## Security Considerations

* Always save encryption credentials securely
* The tool automatically handles key generation and management
* Files are processed in chunks to handle large files efficiently
* All cryptographic operations use strong, modern algorithms

## Acknowledgments
- Built with the cryptography.io library
- GUI implemented using CustomTkinter
- Progress tracking powered by tqdm

## Important Notes

⚠️ **Warnings**:
- Some operating systems and file systems may maintain copies of data in various places (journaling, temp files, etc.)
- The effectiveness of secure deletion may vary depending on the storage medium (especially for SSDs with wear leveling)
- Always verify you have correct files selected before destruction
- The tool cannot decrypt files without correct credentials
- This tool is provided for legitimate data protection purposes only

**ADDITIONAL SECURITY DISCLAIMER**:
This software is provided for general use cases in file encryption and secure deletion. While efforts have been made to ensure security best practices, the authors make no guarantees about the absolute security of the software or its suitability for any specific security requirements. Users should evaluate the software's security properties for their specific use case. The authors are not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

Built with ❤️ by Celso Takeshi Hamasaki
