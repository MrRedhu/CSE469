#!/usr/bin/env python3
"""
bchoc command implementation.

This script supports two commands:
    - init: Initializes the blockchain by creating the Genesis (INITIAL) block.
    - add:  Adds one or more evidence items to the blockchain (each with state CHECKEDIN).

Usage:
    ./bchoc init
    ./bchoc add -c <case_id> -i <item_id> [-i <item_id> ...] -g <creator> -p <password>

The blockchain file path is determined from the environment variable BCHOC_FILE_PATH,
defaulting to "blockchain.dat" if not set.
"""

import os
import sys
import struct
import hashlib
import datetime
import uuid
import argparse
from Crypto.Cipher import AES
import subprocess
import sys

# List of required libraries
required_libraries = ["pycryptodome"]  # Add your required libraries here

for lib in required_libraries:
    try:
        __import__(lib)
    except ImportError:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", lib],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError:
            print(f"> Failed to install {lib}", file=sys.stderr)
            sys.exit(1)
# --------------------------------------------------------------------
# Constants and Block Structure Definitions
# --------------------------------------------------------------------

# Block header structure:
#   - Prev_hash: 32 bytes (32s)
#   - Timestamp: 8 bytes (double, d)
#   - Case_id: 32 bytes (32s)   <- encrypted (hex-encoded from 16-byte AES output)
#   - Evidence_id: 32 bytes (32s)   <- encrypted (hex-encoded from 16-byte AES output)
#   - State: 12 bytes (12s)
#   - Creator: 12 bytes (12s)
#   - Owner: 12 bytes (12s)
#   - Data Length: 4 bytes (unsigned int, I)
BLOCK_FORMAT = "32s d 32s 32s 12s 12s 12s I"
HEADER_SIZE = struct.calcsize(BLOCK_FORMAT)

# AES key for encryption (hard-coded)
AES_KEY = b"R0chLi4uLi4uLi4="  # Provided key (make sure PyCryptodome is installed)

# --------------------------------------------------------------------
# Common Functions (used by both commands)
# --------------------------------------------------------------------

def create_genesis_block():
    """
    Creates and returns the Genesis block (INITIAL block) as a bytes object.
    
    The Genesis block is defined as:
      - Prev_hash: 32 bytes of ASCII "0"
      - Timestamp: 0.0
      - Case_id: 32 bytes of "0"
      - Evidence_id: 32 bytes of "0"
      - State: "INITIAL" padded with 5 null bytes (to 12 bytes)
      - Creator: 12 null bytes
      - Owner: 12 null bytes
      - Data Length: 14
      - Data: b"Initial block\0"
    """
    prev_hash = b"0" * 32
    timestamp = 0.0
    case_id = b"0" * 32
    evidence_id = b"0" * 32
    state = b"INITIAL" + b"\0" * 5
    creator = b"\0" * 12
    owner = b"\0" * 12
    d_length = 14
    data = b"Initial block\0"
    header = struct.pack(BLOCK_FORMAT,
                         prev_hash,
                         timestamp,
                         case_id,
                         evidence_id,
                         state,
                         creator,
                         owner,
                         d_length)
    return header + data

def check_genesis_block(file_path):
    """
    Reads the first block from the blockchain file and verifies that it is the Genesis block.
    """
    try:
        with open(file_path, "rb") as f:
            header_bytes = f.read(HEADER_SIZE)
            if len(header_bytes) != HEADER_SIZE:
                return False, "File too small to contain a valid block."
            unpacked = struct.unpack(BLOCK_FORMAT, header_bytes)
            prev_hash, timestamp, case_id, evidence_id, state, creator, owner, d_length = unpacked
            data_bytes = f.read(d_length)
            expected_state = b"INITIAL" + b"\0" * 5
            if timestamp == 0.0 and case_id == b"0" * 32 and evidence_id == b"0" * 32 and state == expected_state:
                return True, None
            else:
                return False, "Genesis block fields do not match expected values."
    except Exception as e:
        return False, f"Error reading the blockchain file: {e}"

def ensure_blockchain_initialized(file_path):
    """
    Ensures that the blockchain file exists. If not, creates it with the Genesis block.
    """
    if not os.path.exists(file_path):
        genesis_block = create_genesis_block()
        try:
            with open(file_path, "wb") as f:
                f.write(genesis_block)
        except Exception as e:
            print("> Error creating blockchain file:", e, file=sys.stderr)
            sys.exit(1)

def iter_blocks(file_path):
    """
    Generator that yields each block (header + data) from the blockchain file.
    """
    try:
        with open(file_path, "rb") as f:
            while True:
                header = f.read(HEADER_SIZE)
                if not header:
                    break
                if len(header) < HEADER_SIZE:
                    print("> Corrupted blockchain file: incomplete header", file=sys.stderr)
                    sys.exit(1)
                unpacked = struct.unpack(BLOCK_FORMAT, header)
                d_length = unpacked[-1]
                data = f.read(d_length)
                if len(data) < d_length:
                    print("> Corrupted blockchain file: incomplete data", file=sys.stderr)
                    sys.exit(1)
                yield header + data
    except Exception as e:
        print("> Error reading blockchain file:", e, file=sys.stderr)
        sys.exit(1)

def get_existing_item_ids(file_path):
    """
    Returns a set of all encrypted evidence ids already in the blockchain.
    Used to ensure that a new evidence id is unique.
    """
    existing = set()
    for block in iter_blocks(file_path):
        header = block[:HEADER_SIZE]
        unpacked = struct.unpack(BLOCK_FORMAT, header)
        enc_item_id = unpacked[3]  # Evidence_id field
        existing.add(enc_item_id)
    return existing

def get_last_block(file_path):
    """
    Returns the raw bytes of the last block in the blockchain file.
    """
    last = None
    for block in iter_blocks(file_path):
        last = block
    return last

def compute_hash(block_bytes):
    """
    Computes and returns the SHA-256 hash (32 bytes) of the given block bytes.
    """
    return hashlib.sha256(block_bytes).digest()

def pad_field(value, length):
    """
    Pads (or truncates) a byte string to exactly 'length' bytes.
    """
    if len(value) > length:
        return value[:length]
    return value + (b'\0' * (length - len(value)))

# --------------------------------------------------------------------
# Encryption Helpers (used by the add command)
# --------------------------------------------------------------------

def encrypt_field(plaintext):
    """
    Encrypts a 16-byte plaintext using AES ECB mode.
    Returns the 16-byte ciphertext hex-encoded to a 32-byte ASCII string.
    """
    if len(plaintext) != 16:
        print("> Encryption error: plaintext must be 16 bytes", file=sys.stderr)
        sys.exit(1)
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex().encode('ascii')

def encrypt_case_id(case_id_str):
    """
    Encrypts a valid UUID string.
    Converts the UUID to its 16-byte representation, encrypts it, and returns 32 bytes.
    """
    try:
        uuid_obj = uuid.UUID(case_id_str)
    except ValueError:
        print("> Invalid case id", file=sys.stderr)
        sys.exit(1)
    return encrypt_field(uuid_obj.bytes)

def encrypt_item_id(item_id_str):
    """
    Encrypts an evidence (item) id.
    The item id (a 4-byte integer) is packed in big-endian order, padded to 16 bytes, then encrypted.
    """
    try:
        item_int = int(item_id_str)
    except ValueError:
        print("> Invalid item id", file=sys.stderr)
        sys.exit(1)
    packed = struct.pack(">I", item_int)
    padded = packed + (b'\0' * 12)
    return encrypt_field(padded)

# --------------------------------------------------------------------
# Command Implementations
# --------------------------------------------------------------------

def command_init():
    """
    Implements the 'init' command.
    
    If the blockchain file exists, verifies the Genesis block.
    Otherwise, creates a new blockchain file with the Genesis block.
    """
    file_path = os.environ.get("BCHOC_FILE_PATH", "blockchain.dat")
    if os.path.exists(file_path):
        valid, error_message = check_genesis_block(file_path)
        if valid:
            print("> Blockchain file found with INITIAL block.")
            sys.exit(0)
        else:
            print("> Blockchain file found but genesis block is invalid:", error_message, file=sys.stderr)
            sys.exit(1)
    else:
        genesis_block = create_genesis_block()
        try:
            with open(file_path, "wb") as f:
                f.write(genesis_block)
            print("> Blockchain file not found. Created INITIAL block.")
            sys.exit(0)
        except Exception as e:
            print("> Error creating blockchain file:", e, file=sys.stderr)
            sys.exit(1)

def command_add():
    """
    Implements the 'add' command.
    
    Syntax:
      bchoc add -c <case_id> -i <item_id> [-i <item_id> ...] -g <creator> -p <password>
      
    This command adds one or more evidence items to the blockchain. For each evidence item,
    it creates a new block with state CHECKEDIN.
    """
    # Parse the command-line arguments for 'add'
    parser = argparse.ArgumentParser(description="Add evidence items to the blockchain")
    parser.add_argument("-c", "--case", required=True, help="Case identifier (UUID)")
    parser.add_argument("-i", "--item", required=True, action="append",
                        help="Evidence item identifier (4-byte integer). Can be specified multiple times.")
    parser.add_argument("-g", "--creator", required=True, help="Creator identifier")
    parser.add_argument("-p", "--password", required=True, help="Password for creator")
    args = parser.parse_args(sys.argv[2:])  # Parse arguments after "add"

    # Verify the creator's password against the expected value.
    expected_creator_password = os.environ.get("BCHOC_PASSWORD_CREATOR", "C67C")
    if args.password != expected_creator_password:
        print("> Invalid password")
        sys.exit(1)

    file_path = os.environ.get("BCHOC_FILE_PATH", "blockchain.dat")
    ensure_blockchain_initialized(file_path)

    # Encrypt the provided case id.
    encrypted_case_id = encrypt_case_id(args.case)

    # Get a set of all encrypted evidence ids to check for duplicates.
    existing_item_ids = get_existing_item_ids(file_path)

    # Open the blockchain file for appending.
    try:
        f = open(file_path, "ab")
    except Exception as e:
        print("> Error opening blockchain file for appending:", e, file=sys.stderr)
        sys.exit(1)

    # Process each provided evidence item id.
    for item in args.item:
        encrypted_item_id = encrypt_item_id(item)

        # Check for duplicate evidence id.
        if encrypted_item_id in existing_item_ids:
            print(f"> Duplicate evidence id: {item}", file=sys.stderr)
            f.close()
            sys.exit(1)

        # Retrieve the last block to compute its hash.
        last_block = get_last_block(file_path)
        if last_block is None:
            print("> Blockchain file is empty.", file=sys.stderr)
            f.close()
            sys.exit(1)
        prev_hash = compute_hash(last_block)

        # Use the current UTC timestamp.
        timestamp = datetime.datetime.utcnow().timestamp()

        # Set the state to "CHECKEDIN" (padded to 12 bytes).
        state = pad_field(b"CHECKEDIN", 12)

        # Prepare the creator field (padded to 12 bytes).
        creator_bytes = pad_field(args.creator.encode('ascii'), 12)

        # The owner field remains 12 null bytes.
        owner = b"\0" * 12

        # Prepare the Data field.
        data_str = f"Added item: {item}\0"
        data_bytes = data_str.encode('ascii')
        d_length = len(data_bytes)

        # Pack the header.
        header = struct.pack(BLOCK_FORMAT,
                             prev_hash,
                             timestamp,
                             encrypted_case_id,
                             encrypted_item_id,
                             state,
                             creator_bytes,
                             owner,
                             d_length)

        # Concatenate header and data to form the complete block.
        block = header + data_bytes

        # Append the block to the blockchain file.
        try:
            f.write(block)
            f.flush()
        except Exception as e:
            print("> Error writing block to blockchain file:", e, file=sys.stderr)
            f.close()
            sys.exit(1)

        # Print the output.
        timestamp_iso = datetime.datetime.utcfromtimestamp(timestamp).isoformat() + "Z"
        print(f"> Added item: {item}")
        print("> Status: CHECKEDIN")
        print(f"> Time of action: {timestamp_iso}")

        # Update the set to avoid duplicates in the same run.
        existing_item_ids.add(encrypted_item_id)

    f.close()

# --------------------------------------------------------------------
# Main Dispatch
# --------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: bchoc <command> [options]", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1].lower()
    if command == "init":
        command_init()
    elif command == "add":
        command_add()
    else:
        print("Unknown command:", command, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
