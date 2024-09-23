#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status.

function show_help {
    echo "Usage: $0 --input_folder_path=<path> --output_path=<path> [--password=<fd>]"
    echo "  --input_folder_path=<path>  Path to the input folder to be encrypted."
    echo "  --output_path=<path>        Path where the encrypted file will be saved."
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

for i in "$@"
do
case $i in
    --input_folder_path=*)
    INPUT_FOLDER_PATH="${i#*=}"
    shift
    ;;
    --output_path=*)
    OUTPUT_PATH="${i#*=}"
    shift
    ;;
    --password=*)
    PASSWORD_FD="${i#*=}"
    shift
    ;;
    *)
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

if [ -f "${OUTPUT_PATH}.tar.gpg" ] || [ -f "${OUTPUT_PATH}.tar" ] || [ -f "${OUTPUT_PATH}.tar.sha256sum" ]; then
    echo "Error: One or more output files already exist."
    exit 1
fi

# Read the password
if [ -z "$PASSWORD_FD" ]; then
    echo "Please enter the password: "
    read -s PASSWORD
else
    read -u "$PASSWORD_FD" PASSWORD
fi

# Encrypt and hash the folder
tar -cf "${OUTPUT_PATH}.tar" -C "$(dirname "$INPUT_FOLDER_PATH")" "$(basename "$INPUT_FOLDER_PATH")"
echo "$PASSWORD" | gpg --batch --yes --passphrase-fd 0 --symmetric --cipher-algo AES256 -o "${OUTPUT_PATH}.tar.gpg" "${OUTPUT_PATH}.tar"
echo "$PASSWORD" | (cat "${OUTPUT_PATH}.tar" -) | sha256sum > "${OUTPUT_PATH}.tar.sha256sum"
rm "${OUTPUT_PATH}.tar"

echo "Encryption and signing completed successfully."
