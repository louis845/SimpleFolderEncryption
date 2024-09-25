# Folder Encryption and Decryption Scripts

Simple command-line tools to securely encrypt and decrypt folders using GPG and SHA-256 checksums.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Encrypting a Folder](#encrypting-a-folder)
  - [Decrypting a Folder](#decrypting-a-folder)
- [Examples](#examples)
- [Security Considerations](#security-considerations)
- [License](#license)

## Overview

This repository provides two Bash scripts, `encrypt.sh` and `decrypt.sh`, designed to simplify the process of encrypting and decrypting folders via the command line. The encryption process bundles the folder into a tar archive, encrypts it using GPG with AES256 cipher, and generates a SHA-256 checksum for integrity verification. Decryption reverses these steps, ensuring the integrity and confidentiality of your data.
**DO NOT RELY ON THIS FOR HIGH SECURITY USE CASES!** This code only provides a basic interface for encrypting folders. For more sophisticated needs, a comprehensive analysis of the use case (e.g salting and so on) have to be conducted.

## Features

- **Easy encryption of folders with GPG:** Utilizes GPG with AES256 cipher with a method to tarball a folder for encryption.
- **Integrity Verification:** Generates and verifies SHA-256 checksums to ensure data integrity.
- **Flexible Password Handling:** Allows password input via standard input or file descriptor, so the script(s) can be run on its own or invoked by other scripts.

## Requirements

- **Operating System:** Linux
- **Shell:** Bash
- **Dependencies:**
  - [`tar`](https://www.gnu.org/software/tar/)
  - [`gpg`](https://gnupg.org/)
  - [`sha256sum`](https://www.gnu.org/software/coreutils/)

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/louis845/SimpleFolderEncryption
   cd SimpleFolderEncryption
   ```

2. **Make Scripts Executable:**

   ```bash
   chmod +x encrypt.sh decrypt.sh
   ```

3. **(Optional) Edit .bashrc (or whatever rc) to include the scripts in your PATH**

## Usage

**IMPORTANT**: For the `--password` option, this is ***not*** to input the password! Passing passwords to a script via the command line is
somewhat insecure, as it can be potentially eavesdropped by other programs. Therefore, the password indicates a file descriptor as an input
and reads from the file descriptor. Alternatively, if not provided, the script will prompt you for the password. It is **recommended** that
`--password` to never be used if the script(s) are always used as a standalone script.

### Encrypting a Folder

```bash
./encrypt.sh --input_folder_path=<path_to_folder> --output_path=<output_file_path> [--password=<fd>]
```

#### Arguments

- `--input_folder_path=<path>`  
  **Required.** Path to the input folder you want to encrypt.

- `--output_path=<path>`  
  **Required.** Base path where the encrypted file and checksum will be saved. The script appends `.tar.gpg` and `.tar.sha256sum` to this path.

- `--password=<fd>`  
  **Optional.** File descriptor for reading the password. If not provided, the script will prompt you to enter a password interactively.

#### Example

```bash
./encrypt.sh --input_folder_path=/home/user/Documents/Secrets --output_path=/home/user/Encrypted/SecretsEncrypted
```

#### Password Handling

- **Interactive Password Entry:**
  
  If `--password` is not specified, the script will prompt:

  ```bash
  Please enter the password:
  ```

  The password input will be hidden for security.

- **File Descriptor:**
  
  You can provide a file descriptor to read the password, useful for scripting:

  ```bash
  exec 3< /path/to/password-file
  ./encrypt.sh --input_folder_path=/path/to/folder --output_path=/path/to/output --password=3
  exec 3<&-
  ```

### Decrypting a Folder

```bash
./decrypt.sh --input_path=<encrypted_file_path> --output_folder_path=<path_to_extract> [--password=<fd>]
```

#### Arguments

- `--input_path=<path>`  
  **Required.** Base path to the encrypted `.tar.gpg` file. The script also expects a corresponding `.tar.sha256sum` file in the same directory.

- `--output_folder_path=<path>`  
  **Required.** Path where the decrypted files will be extracted. The directory must already exist.

- `--password=<fd>`  
  **Optional.** File descriptor for reading the password. If not provided, the script will prompt you to enter a password interactively.

#### Example

```bash
./decrypt.sh --input_path=/home/user/Encrypted/SecretsEncrypted --output_folder_path=/home/user/Documents/
```

#### Password Handling

- **Interactive Password Entry:**
  
  If `--password` is not specified, the script will prompt:

  ```bash
  Please enter the password:
  ```

  The password input will be hidden for security.

- **File Descriptor:**
  
  You can provide a file descriptor to read the password, useful for scripting:

  ```bash
  exec 3< /path/to/password-file
  ./decrypt.sh --input_path=/path/to/encrypted_file --output_folder_path=/path/to/extract --password=3
  exec 3<&-
  ```

## Examples

### Encrypting a Folder Interactively

```bash
./encrypt.sh --input_folder_path=/home/user/MyFolder --output_path=/home/user/MyFolderEncrypted
```

**Output:**

```
Please enter the password:
Encryption and signing completed successfully.
```

**Generated Files:**

- `/home/user/MyFolderEncrypted.tar.gpg`
- `/home/user/MyFolderEncrypted.tar.sha256sum`

### Decrypting a Folder Interactively

```bash
./decrypt.sh --input_path=/home/user/MyFolderEncrypted --output_folder_path=/home/user/Recovered
```

**Output:**

```
Please enter the password:
Decryption and verification completed successfully.
```

The contents of `MyFolder` will be extracted to `/home/user/Recovered`.

### Encrypting with Password File Descriptor

```bash
exec 3< /home/user/password.txt
./encrypt.sh --input_folder_path=/home/user/MyFolder --output_path=/home/user/MyFolderEncrypted --password=3
exec 3<&-
```

### Decrypting with Password File Descriptor

```bash
exec 3< /home/user/password.txt
./decrypt.sh --input_path=/home/user/MyFolderEncrypted --output_folder_path=/home/user/Recovered --password=3
exec 3<&-
```

## Security Considerations

- **Password Security:**  
  Ensure that passwords are handled securely. Avoid exposing passwords in command histories or scripts. Utilize file descriptors or environment variables carefully to prevent accidental leaks.

- **File Permissions:**  
  Restrict access to encrypted files and password files to authorized users only.

- **Backup:**  
  Always keep backups of your encrypted data and password in secure locations to prevent data loss.

- **GPG Trust:**  
  The scripts use symmetric encryption with a passphrase. For higher security, consider using GPG with public/private keys.

## License

This project is licensed under the [Apache 2.0 License](LICENSE)

---

*Thanks for viewing SimpleFolderEncryption!*
