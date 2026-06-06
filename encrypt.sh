#!/bin/bash

set -e          # Exit immediately if a command exits with a non-zero status.
set -o pipefail # Ensure pipeline failures are caught (e.g., if tar fails, gpg won't silently create a bad file).

function show_help {
    echo "Usage: $0 --input_folder_path=<path> --output_path=<path> [--password=<fd>]"
    echo "  --input_folder_path=<path>  Path to the input folder to be encrypted."
    echo "  --output_path=<path>        Base path where the encrypted file will be saved (will append .tar.gpg)."
    echo "  --password=<fd>             Optional file descriptor for reading the password."
}

if [[ "$#" -lt 2 ]]; then
    echo "Error: Missing required arguments."
    show_help
    exit 1
fi

# Parse command line arguments
INPUT_FOLDER_PATH=""
OUTPUT_PATH=""
PASSWORD_FD=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --input_folder_path=*)
        INPUT_FOLDER_PATH="${1#*=}"
        shift
        ;;
        --output_path=*)
        OUTPUT_PATH="${1#*=}"
        shift
        ;;
        --password=*)
        PASSWORD_FD="${1#*=}"
        shift
        ;;
        *)
        echo "Unknown parameter passed: $1"
        show_help
        exit 1
        ;;
    esac
done

# Validate input arguments
if [ ! -d "$INPUT_FOLDER_PATH" ]; then
    echo "Error: Input folder path does not exist."
    exit 1
fi

if [ -f "${OUTPUT_PATH}.tar.gpg" ]; then
    echo "Error: Output file ${OUTPUT_PATH}.tar.gpg already exists."
    exit 1
fi

# Read the password
if [ -z "$PASSWORD_FD" ]; then
    read -rs -p "Please enter the password: " PASSWORD
    echo "" # Add a newline after silent input
else
    read -ru "$PASSWORD_FD" PASSWORD
fi

# Encrypt the folder securely using pipes
# tar writes to standard output (-), and gpg encrypts that stream directly to the output file.
# We use File Descriptor 3 (3<<<"$PASSWORD") to pass the password to GPG securely.
tar -cf - -C "$(dirname "$INPUT_FOLDER_PATH")" "$(basename "$INPUT_FOLDER_PATH")" | \
    gpg --batch --yes --passphrase-fd 3 --symmetric --cipher-algo AES256 -o "${OUTPUT_PATH}.tar.gpg" 3<<<"$PASSWORD"

echo "Encryption completed successfully. Integrity checks are embedded in the GPG file."
