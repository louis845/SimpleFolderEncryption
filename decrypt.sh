#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status.

function show_help {
    echo "Usage: $0 --input_path=<path> --output_folder_path=<path> [--password=<fd>]"
    echo "  --input_path=<path>          Path to the encrypted tar.gpg file to be decrypted."
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

for i in "$@"
do
case $i in
    --input_path=*)
    INPUT_PATH="${i#*=}"
    shift
    ;;
    --output_folder_path=*)
    OUTPUT_FOLDER_PATH="${i#*=}"
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
if [ ! -f "${INPUT_PATH}.tar.gpg" ] || [ ! -f "${INPUT_PATH}.tar.sha256sum" ]; then
    echo "Error: Required input files do not exist."
    exit 1
fi

if [ -d "$OUTPUT_FOLDER_PATH" ]; then
    echo "Error: Output folder already exists."
    exit 1
fi

# Read the password
if [ -z "$PASSWORD_FD" ]; then
    echo "Please enter the password: "
    read -s PASSWORD
else
    read -u "$PASSWORD_FD" PASSWORD
fi

echo "$PASSWORD" | gpg --batch --yes --passphrase-fd 0 --decrypt -o "${INPUT_PATH}.tar" "${INPUT_PATH}.tar.gpg"
CHECKSUM=$(cat "${INPUT_PATH}.tar.sha256sum")
CALCULATED_CHECKSUM=$(echo "$PASSWORD" | (cat "${INPUT_PATH}.tar" -) | sha256sum)
if [[ "$CHECKSUM" != "$CALCULATED_CHECKSUM" ]]; then
    echo "Integrity check failed!"
    exit 2
fi

mkdir -p "$OUTPUT_FOLDER_PATH"
tar -xf "${INPUT_PATH}.tar" -C "$OUTPUT_FOLDER_PATH"
rm "${INPUT_PATH}.tar"

echo "Decryption and verification completed successfully."
