import os
import subprocess
import sys
import hashlib
import getpass
import argparse

def encrypt_folder(input_folder_path: str, output_path: str, password: str) -> None:
    """
    Encrypts a folder using GPG symmetric encryption and creates a SHA256 checksum.

    Args:
        input_folder_path (str): Path to the input folder to be encrypted.
        output_path (str): Path where the encrypted file will be saved (without extensions).
        password (str): Password used for encryption.

    Raises:
        FileNotFoundError: If the input folder does not exist.
        FileExistsError: If any of the output files already exist.
        ValueError: If required arguments are missing or invalid.
        subprocess.CalledProcessError: If any subprocess command fails.
    """
    if (not isinstance(input_folder_path, str)) or (not isinstance(output_path, str)) or (not isinstance(password, str)):
        raise ValueError("Invalid formats!")

    # Validate input_folder_path
    if not os.path.isdir(input_folder_path):
        raise FileNotFoundError(
            f"Error: Input folder path '{input_folder_path}' does not exist or is not a directory."
        )

    # Define the expected output files
    tar_path = f"{output_path}.tar"
    gpg_path = f"{output_path}.tar.gpg"
    sha256_path = f"{output_path}.tar.sha256sum"

    # Check if any of the output files already exist
    if any(os.path.exists(path) for path in [tar_path, gpg_path, sha256_path]):
        raise FileExistsError("Error: One or more output files already exist.")

    # Ensure password is not empty
    if not password:
        raise ValueError("Password cannot be empty.")

    # Create a tar archive of the input folder
    try:
        input_dir = os.path.dirname(os.path.abspath(input_folder_path))
        input_basename = os.path.basename(os.path.abspath(input_folder_path))
        subprocess.run(
            ['tar', '-cf', tar_path, '-C', input_dir, input_basename],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError as e:
        raise subprocess.CalledProcessError(
            returncode=e.returncode,
            cmd=e.cmd,
            output=e.output.decode(),
            stderr=e.stderr.decode()
        ) from e

    # Encrypt the tar file using GPG with symmetric encryption
    try:
        subprocess.run(
            [
                'gpg', '--batch', '--yes', '--passphrase-fd', '0',
                '--symmetric', '--cipher-algo', 'AES256', '-o', gpg_path, tar_path
            ],
            input=(password + '\n').encode(),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError as e:
        # Clean up the tar file if encryption fails
        if os.path.exists(tar_path):
            os.remove(tar_path)
        raise subprocess.CalledProcessError(
            returncode=e.returncode,
            cmd=e.cmd,
            output=e.output.decode(),
            stderr=e.stderr.decode()
        ) from e

    # Calculate SHA256 checksum of the concatenated password and tar file
    try:
        sha256_hash = hashlib.sha256()
        with open(tar_path, 'rb') as tar_file:
            for chunk in iter(lambda: tar_file.read(4096), b""):
                sha256_hash.update(chunk)
        sha256_hash.update((password + "\n").encode()) # Need to add newline at the back since echo adds a newline by default.
        checksum = sha256_hash.hexdigest()
        with open(sha256_path, 'w') as sha_file:
            sha_file.write(f"{checksum}  -")
    except Exception as e:
        # Clean up if hashing fails
        if os.path.exists(tar_path):
            os.remove(tar_path)
        if os.path.exists(gpg_path):
            os.remove(gpg_path)
        raise e

    # Remove the tar file as it's no longer needed
    os.remove(tar_path)

    print(f"Encryption completed successfully for '{input_folder_path}'.")


def decrypt_folder(input_path: str, output_folder_path: str, password: str) -> None:
    """
    Decrypts an encrypted tar.gpg file and verifies its integrity using SHA256 checksum.

    Args:
        input_path (str): Path to the encrypted tar.gpg file (without extensions).
        output_folder_path (str): Path where the decrypted files will be extracted.
        password (str): Password used for decryption.

    Raises:
        FileNotFoundError: If required input files do not exist or output folder does not exist.
        ValueError: If passwords are invalid or integrity check fails.
        subprocess.CalledProcessError: If any subprocess command fails.
    """
    if (not isinstance(input_path, str)) or (not isinstance(output_folder_path, str)) or (not isinstance(password, str)):
        raise ValueError("Invalid formats!")

    # Define the expected input files
    gpg_path = f"{input_path}.tar.gpg"
    sha256_path = f"{input_path}.tar.sha256sum"
    tar_path = f"{input_path}.tar"

    # Validate that the encrypted file and checksum exist
    if not os.path.isfile(gpg_path):
        raise FileNotFoundError(f"Error: Encrypted file '{gpg_path}' does not exist.")
    if not os.path.isfile(sha256_path):
        raise FileNotFoundError(f"Error: Checksum file '{sha256_path}' does not exist.")
    if os.path.isfile(tar_path):
        raise ValueError("Error: Do not expect that the tar path exists!")

    # Validate output_folder_path
    if (not os.path.isdir(output_folder_path)) or (not os.access(output_folder_path, os.W_OK)) or (not os.access(output_folder_path, os.X_OK)):
        raise FileNotFoundError(
            f"Error: Output folder path '{output_folder_path}' does not exist or is not a writable directory."
        )
    if len(os.listdir(output_folder_path)) > 0:
        raise ValueError("Expected output folder path to be empty.")

    # Ensure password is not empty
    if not password:
        raise ValueError("Password cannot be empty.")

    # Decrypt the GPG encrypted tar file
    try:
        subprocess.run(
            [
                'gpg', '--batch', '--yes', '--passphrase-fd', '0',
                '--decrypt', '-o', tar_path, gpg_path
            ],
            input=(password + '\n').encode(),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError as e:
        raise subprocess.CalledProcessError(
            returncode=e.returncode,
            cmd=e.cmd,
            output=e.output.decode(),
            stderr=e.stderr.decode()
        ) from e

    # Read the stored checksum
    try:
        with open(sha256_path, 'r') as sha_file:
            stored_checksum_line = sha_file.readline()
            stored_checksum = stored_checksum_line.split()[0]
    except Exception as e:
        # Clean up the tar file if reading checksum fails
        if os.path.exists(tar_path):
            os.remove(tar_path)
        raise e

    # Calculate the SHA256 checksum of the concatenated password and tar file
    try:
        sha256_hash = hashlib.sha256()
        with open(tar_path, 'rb') as tar_file:
            for chunk in iter(lambda: tar_file.read(4096), b""):
                sha256_hash.update(chunk)
        sha256_hash.update((password + "\n").encode()) # Need to add newline at the back since echo adds a newline by default.
        calculated_checksum = sha256_hash.hexdigest()
    except Exception as e:
        # Clean up the tar file if hashing fails
        if os.path.exists(tar_path):
            os.remove(tar_path)
        raise e

    # Verify the checksum
    if stored_checksum != calculated_checksum:
        # Clean up the tar file if integrity check fails
        if os.path.exists(tar_path):
            os.remove(tar_path)
        raise ValueError("Integrity check failed! The decrypted data may be corrupted or the password is incorrect.")

    # Extract the tar file to the output directory
    try:
        subprocess.run(
            ['tar', '-xf', tar_path, '-C', output_folder_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError as e:
        # Clean up the tar file if extraction fails
        if os.path.exists(tar_path):
            os.remove(tar_path)
        raise subprocess.CalledProcessError(
            returncode=e.returncode,
            cmd=e.cmd,
            output=e.output.decode(),
            stderr=e.stderr.decode()
        ) from e

    # Remove the tar file as it's no longer needed
    os.remove(tar_path)

    print(f"Decryption and verification completed successfully for '{input_path}'.")


def prompt_encrypt_folder(input_folder_path: str, output_path: str) -> None:
    """
    Prompts the user for a password and encrypts the specified folder.

    Args:
        input_folder_path (str): Path to the input folder to be encrypted.
        output_path (str): Path where the encrypted file will be saved (without extensions).

    Raises:
        Exception: Propagates exceptions from encrypt_folder.
    """
    try:
        # Prompt the user for a password without echoing
        password = getpass.getpass("Please enter the password: ")
        password_confirm = getpass.getpass("Please confirm the password: ")
        if password != password_confirm:
            raise ValueError("Passwords do not match.")

        encrypt_folder(input_folder_path, output_path, password)
    except Exception as e:
        print(f"Encryption failed for '{input_folder_path}': {e}")


def prompt_decrypt_folder(input_path: str, output_folder_path: str) -> None:
    """
    Prompts the user for a password and decrypts the specified encrypted file.

    Args:
        input_path (str): Path to the encrypted tar.gpg file (without extensions).
        output_folder_path (str): Path where the decrypted files will be extracted.

    Raises:
        Exception: Propagates exceptions from decrypt_folder.
    """
    try:
        # Prompt the user for a password without echoing
        password = getpass.getpass("Please enter the password: ")

        decrypt_folder(input_path, output_folder_path, password)
    except Exception as e:
        print(f"Decryption failed for '{input_path}': {e}")


def prompt_encrypt_bulk_subfolders(parent_folder_path: str, output_directory: str) -> None:
    """
    Prompts the user for a password and encrypts all subfolders within the specified parent folder.
    Each subfolder is encrypted into its own .tar.gpg and .tar.sha256sum pair based on the subfolder's basename.

    Args:
        parent_folder_path (str): Path containing subfolders to encrypt.
        output_directory (str): Path where encrypted files will be saved.

    Raises:
        Exception: Propagates exceptions from encrypt_folder.
    """
    try:
        # Validate parent_folder_path
        if not os.path.isdir(parent_folder_path):
            raise FileNotFoundError(
                f"Error: Parent folder path '{parent_folder_path}' does not exist or is not a directory."
            )

        # Validate or create output_directory
        if not os.path.isdir(output_directory):
            try:
                os.makedirs(output_directory)
                print(f"Created output directory '{output_directory}'.")
            except Exception as e:
                raise IOError(f"Unable to create output directory '{output_directory}': {e}")

        # Prompt the user for a password without echoing
        password = getpass.getpass("Please enter the password for all subfolders: ")
        password_confirm = getpass.getpass("Please confirm the password: ")
        if password != password_confirm:
            raise ValueError("Passwords do not match.")

        # Iterate through subfolders and encrypt each
        for entry in os.scandir(parent_folder_path):
            if entry.is_dir():
                subfolder_path = entry.path
                subfolder_basename = os.path.basename(subfolder_path)
                encrypted_output_path = os.path.join(output_directory, subfolder_basename)

                try:
                    print(f"Encrypting '{subfolder_basename}'...")
                    encrypt_folder(subfolder_path, encrypted_output_path, password)
                except FileExistsError:
                    print(f"Skipped '{subfolder_basename}': Encrypted files already exist.")
                except Exception as e:
                    print(f"Failed to encrypt '{subfolder_basename}': {e}")

        print("Bulk encryption of subfolders completed successfully.")
    except Exception as e:
        print(f"Bulk encryption failed: {e}")
