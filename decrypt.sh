#!/bin/bash

set -e          # Exit immediately if a command exits with a non-zero status.
set -o pipefail # Ensure pipeline failures are caught (e.g., if gpg fails, tar won't run).

function show_help {
    echo "Usage: $0 --input_path=<path> --output_folder_path=<path> [--password=<fd>]"
    echo "  --input_path=<path>          Base path to the encrypted file (script appends .tar.gpg)."
    echo "  --output_folder_path=<path>  Path where the decrypted files will be extracted."
    echo "  --password=<fd>              Optional file descriptor for reading the password."
}

if [[ "$#" -lt 2 ]]; then
    echo "Error: Missing required arguments."
    show_help
    exit 1
fi

# Parse command line arguments
INPUT_PATH=""
OUTPUT_FOLDER_PATH=""
PASSWORD_FD=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --input_path=*)
        INPUT_PATH="${1#*=}"
        shift
        ;;
        --output_folder_path=*)
        OUTPUT_FOLDER_PATH="${1#*=}"
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
if [ ! -f "${INPUT_PATH}.tar.gpg" ]; then
    echo "Error: Required input file ${INPUT_PATH}.tar.gpg does not exist."
    exit 1
fi

if [ ! -d "$OUTPUT_FOLDER_PATH" ]; then
    echo "Error: Output folder path does not exist."
    exit 1
fi

# Read the password
if [ -z "$PASSWORD_FD" ]; then
    read -rs -p "Please enter the password: " PASSWORD
    echo "" # Add a newline after silent input
else
    read -ru "$PASSWORD_FD" PASSWORD
fi

# Decrypt and extract securely using pipes
# GPG decrypts the file, verifies its internal integrity, and pipes the plaintext directly into tar.
# If the password is wrong or the file is corrupted, GPG will fail and pipefail will stop tar.
gpg --batch --yes --passphrase-fd 3 --decrypt "${INPUT_PATH}.tar.gpg" 3<<<"$PASSWORD" | \
    tar -xf - -C "$OUTPUT_FOLDER_PATH"

echo "Decryption and verification completed successfully."
