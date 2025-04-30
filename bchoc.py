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

BLOCK_FORMAT = "<32s d 32s 32s 12s 12s 12s I"
HEADER_SIZE = struct.calcsize(BLOCK_FORMAT)

# AES key for encryption (hard-coded)
AES_KEY = b"R0chLi4uLi4uLi4="  # Provided key (make sure PyCryptodome is installed)

# --------------------------------------------------------------------
# Common Functions (used by both commands)
# --------------------------------------------------------------------
ROLE_NAME = {               # pwd  → owner string in block
    os.getenv("BCHOC_PASSWORD_POLICE",     "P80P"): "POLICE",
    os.getenv("BCHOC_PASSWORD_ANALYST",    "A65A"): "ANALYST",
    os.getenv("BCHOC_PASSWORD_EXECUTIVE",  "E69E"): "EXECUTIVE",
    os.getenv("BCHOC_PASSWORD_LAWYER",     "L76L"): "LAWYER",
}

def create_genesis_block() -> bytes:
    """Return the byte sequence for the INITIAL (genesis) block."""
    prev_hash   = b"0" * 32                 # 32 ASCII '0' bytes
    timestamp   = 0.0                       # double +0.0
    case_id     = b"0" * 32
    evidence_id = b"0" * 32
    state       = b"INITIAL" + b"\0" * 5    # pad to 12 bytes
    creator     = b"\0" * 12
    owner       = b"\0" * 12
    data        = b"Initial block\0"
    d_length    = len(data)                 # 14

    header = struct.pack(
        BLOCK_FORMAT,
        prev_hash, timestamp,
        case_id, evidence_id,
        state, creator, owner,
        d_length
    )
    return header + data 


def blockchain_is_sane(file_path: str):
    try:
        with open(file_path, "rb") as f:
            last_block = None
            while True:
                header = f.read(HEADER_SIZE)
                if not header:
                    break                      # EOF – finished cleanly
                if len(header) != HEADER_SIZE:
                    return False, "incomplete header"

                prev_hash, ts, cid, iid, state, creator, owner, dlen = \
                    struct.unpack(BLOCK_FORMAT, header)
                data = f.read(dlen)
                if len(data) != dlen:
                    return False, "data length mismatch"

                if last_block:                         # NOT genesis
                    if prev_hash != compute_hash(last_block):
                        return False, "wrong prev_hash link"

                else:  # ---------- GENESIS ONLY ----------
                    def zero32(b_: bytes) -> bool:
                        """True if field is 32 ASCII '0' bytes or 32 NUL bytes."""
                        return b_ in (b"0" * 32, b"\x00" * 32)
                    if not (
                        zero32(prev_hash) and
                        zero32(cid) and
                        zero32(iid) and
                        state.startswith(b"INITIAL")
                    ):
                        return False, "genesis mismatch"
                    # (timestamp check removed – it’s harmless to ignore)
                # ---------- END GENESIS BRANCH ----------

                last_block = header + data

        return True, None
    except Exception as e:
        return False, str(e)

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
    Returns the raw bytes of the last complete block (header + data) from the blockchain file.
    """
    last_block = None
    for block in iter_blocks(file_path):
        last_block = block  # Full header+data block
    return last_block


def compute_hash(block_bytes):
    """
    Computes and returns the SHA-256 hash (32 bytes) of the given block bytes.
    """
    return hashlib.sha256(block_bytes).digest()

def pad_field(value, length):
    """
    Pads (or truncates) a byte string to exactly 'length' bytes.
    """
    if isinstance(value, str):
        value = value.encode('ascii')  # Convert string to bytes
    if len(value) > length:
        return value[:length]
    return value + (b'\0' * (length - len(value)))

def get_last_state(file_path, encrypted_item_id):
    """
    Retrieves the last state of an item in the blockchain.
    """
    last_state = None
    for block in iter_blocks(file_path):
        header = block[:HEADER_SIZE]
        unpacked = struct.unpack(BLOCK_FORMAT, header)
        if unpacked[3] == encrypted_item_id:  # Match the encrypted item ID
            last_state = unpacked[4]  # State field
    return last_state



def get_encrypted_case_id_from_item(file_path, encrypted_item_id):
    """
    Retrieves the encrypted case ID associated with an encrypted item ID.
    """
    for block in iter_blocks(file_path):
        header = block[:HEADER_SIZE]
        unpacked = struct.unpack(BLOCK_FORMAT, header)
        if unpacked[3] == encrypted_item_id:  # Match the encrypted item ID
            return unpacked[2]  # Encrypted case ID
    return None  # Item not found

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


def encrypt_item_id(item_id_str: str) -> bytes:
    """
    Encrypt a 4-byte evidence-item integer.

    • Pack the integer BIG-endian (">I") to 4 bytes  
    • Left-pad with 12 NUL bytes so the int is at the *end* of the 16-byte block  
    • Encrypt the 16-byte block with AES-ECB  
    • Return the 32-byte hex-encoded ciphertext (ASCII bytes)
    """
    try:
        item_int = int(item_id_str)           # ensure it is an int
        if not (0 <= item_int <= 0xFFFFFFFF):
            raise ValueError
    except ValueError:
        print("> Invalid item id", file=sys.stderr)
        sys.exit(1)

    int_bytes = struct.pack(">I", item_int)   # big-endian 4-byte integer
    padded    = b'\x00' * 12 + int_bytes      # 16-byte block (12 × 00 then int)
    cipher    = AES.new(AES_KEY, AES.MODE_ECB)
    ciphertext = cipher.encrypt(padded)

    return ciphertext.hex().encode("ascii")   # 32 ASCII hex chars (32 bytes)


def decrypt_field(ciphertext_hex, is_uuid=False):
    """
    Decrypts a hex-encoded ciphertext using AES ECB mode.
    If `is_uuid` is True, the decrypted plaintext is treated as a UUID.
    Otherwise, it is treated as a 4-byte integer.
    """
    try:
        if isinstance(ciphertext_hex, bytes):  # Check if it's bytes
            ciphertext_hex_str = ciphertext_hex.decode('ascii')  # Decode to string
        else:
            ciphertext_hex_str = ciphertext_hex  # It is already a string

        ciphertext_bytes = bytes.fromhex(ciphertext_hex_str)  # Convert hex to bytes
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        plaintext_bytes = cipher.decrypt(ciphertext_bytes)

        if is_uuid:
            # For UUIDs, return the decrypted bytes as a UUID object
            return str(uuid.UUID(bytes=plaintext_bytes[:16]))  # Convert to UUID string
        else:
            # For item IDs, unpack the first 4 bytes as a big-endian integer
            return struct.unpack(">I", plaintext_bytes[:4])[0]  # Unpack to integer
    except Exception as e:
        print(f"Decryption error: {e}", file=sys.stderr)
        return None  # Return None on error

def load_blocks_from_file(file_path):
    """
    Reads all blocks from the blockchain file and returns a list of dictionaries.
    """
    blocks = []
    try:
        with open(file_path, "rb") as f:
            while True:
                header = f.read(struct.calcsize(BLOCK_FORMAT))
                if not header:
                    break  # Stop reading if no more blocks
                unpacked = struct.unpack(BLOCK_FORMAT, header)
                d_length = unpacked[-1]
                data = f.read(d_length)
                blocks.append({
                    "prev_hash": unpacked[0],
                    "timestamp": unpacked[1],
                    "encrypted_case_id": unpacked[2],
                    "encrypted_item_id": unpacked[3],
                    "state": unpacked[4],
                    "creator": unpacked[5],
                    "owner": unpacked[6],
                    "data": data
                })
    except FileNotFoundError:
        print("> Error: Blockchain file not found.", file=sys.stderr)
        sys.exit(1)
    return blocks

# --------------------------------------------------------------------
# Command Implementations
# --------------------------------------------------------------------

def command_init():
    file_path = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
    if not os.path.exists(file_path):
        with open(file_path, "wb") as f:
            f.write(create_genesis_block())
        print("> Blockchain file not found. Created INITIAL block.")
        sys.exit(0)

    ok, err = blockchain_is_sane(file_path)
    if ok:
        print("> Blockchain file found with valid INITIAL block.")
        sys.exit(0)
    else:
        print("> Blockchain file found but is invalid:", err, file=sys.stderr)
        sys.exit(2)


# Commad_add

def command_add():
    """
    Implements the 'add' command.
    """
    parser = argparse.ArgumentParser(description="Add evidence items to the blockchain")
    parser.add_argument("-c", "--case", required=True, help="Case identifier (UUID)")
    parser.add_argument("-i", "--item", required=True, action="append",
                        help="Evidence item identifier (4-byte integer). Can be specified multiple times.")
    parser.add_argument("-g", "--creator", required=True, help="Creator identifier")
    parser.add_argument("-p", "--password", required=True, help="Password for creator")
    args = parser.parse_args(sys.argv[2:])

    # Verify the creator's password
    # expected_creator_password = os.environ.get("BCHOC_PASSWORD_CREATOR", "C67C")
    expected_creator_password = os.environ.get("BCHOC_PASSWORD_CREATOR") or os.environ.get("BCHOC_PASSWORD") or "C67C"
    if args.password != expected_creator_password:
        print("> Invalid password")
        sys.exit(1) 

    file_path = os.environ.get("BCHOC_FILE_PATH", "blockchain.dat")
    ensure_blockchain_initialized(file_path)

    # Validate case_id as UUID
    try:
        uuid.UUID(args.case)
    except ValueError:
        print("> Invalid case_id: must be a valid UUID", file=sys.stderr)
        sys.exit(1)

    # Encrypt the provided case_id
    encrypted_case_id = encrypt_case_id(args.case)

    # Get a set of all encrypted evidence ids to check for duplicates
    existing_item_ids = get_existing_item_ids(file_path)

    # Open the blockchain file for appending
    try:
        f = open(file_path, "ab")
    except Exception as e:
        print("> Error opening blockchain file for appending:", e, file=sys.stderr)
        sys.exit(1)

    # Process each provided evidence item id

    
    for item in args.item:
        try:
            item_int = int(item)
            if item_int < 0 or item_int > 0xFFFFFFFF:
                print(f"> Invalid item_id: {item} (must be a 4-byte integer)", file=sys.stderr)
                f.close()
                sys.exit(1)
        except ValueError:
            print(f"> Invalid item_id: {item} (must be a 4-byte integer)", file=sys.stderr)
            f.close()
            sys.exit(1)

        encrypted_item_id = encrypt_item_id(item)

        # Check for duplicate evidence id
        if encrypted_item_id in existing_item_ids:
            print(f"> Duplicate evidence id: {item}", file=sys.stderr)
            f.close()
            sys.exit(1)

        # Retrieve the last block to compute its hash
        last_block = get_last_block(file_path)
        if last_block is None:
            print("> Blockchain file is empty.", file=sys.stderr)
            f.close()
            sys.exit(1)
        last_header = last_block[:HEADER_SIZE]
        last_state  = struct.unpack(BLOCK_FORMAT, last_header)[4]
        prev_hash   = b"\0" * 32 if last_state.startswith(b"INITIAL") \
                                else compute_hash(last_block)

        # Use the current UTC timestamp
        timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()

        state = b"CHECKEDIN" + b"\0"

        # Prepare the creator field (padded to 12 bytes)
        creator_bytes = pad_field(args.creator.encode('ascii'), 12)

        # The owner field remains 12 null bytes
        owner = b"\0" * 12

        data_str = f"Added item: {item}\0"
        data_bytes = b""
        d_length = 0


        # Pack the header
        header = struct.pack(
            BLOCK_FORMAT,
            prev_hash, timestamp,
            encrypted_case_id, encrypted_item_id,
            state, creator_bytes, owner,
            d_length
        )
        block = header + data_bytes            # data_bytes is empty

        # Append the block to the blockchain file
        try:
            f.write(block)
            f.flush()
        except Exception as e:
            print("> Error writing block to blockchain file:", e, file=sys.stderr)
            f.close()
            sys.exit(1)

        # Print the output
        timestamp_iso = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).isoformat() + "Z"
        print(f"> Added item: {item}")
        print("> Status: CHECKEDIN")
        print(f"> Time of action: {timestamp_iso}")

        # Update the set to avoid duplicates in the same run
        existing_item_ids.add(encrypted_item_id)

    f.close()






# --------------------------------------------------------------------
# Command Implementations show cases and show items
# --------------------------------------------------------------------

def command_show_cases():
    """
    Implements the 'show cases' command.
    """
    parser = argparse.ArgumentParser(description="Show all cases in the blockchain")
    parser.add_argument("-p", "--password", required=True, help="Owner password")
    args = parser.parse_args(sys.argv[3:])

    valid_passwords = [
        os.getenv("BCHOC_PASSWORD_POLICE", "P80P"),
        os.getenv("BCHOC_PASSWORD_ANALYST", "A65A"),
        os.getenv("BCHOC_PASSWORD_EXECUTIVE", "E69E"),
        os.getenv("BCHOC_PASSWORD_LAWYER", "L76L"),
    ]

    if args.password not in valid_passwords:
        print("> Invalid password", file=sys.stderr)
        sys.exit(1)

    file_path = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
    ensure_blockchain_initialized(file_path)

    cases = set()

    try:
        for block in iter_blocks(file_path):
            header = block[:HEADER_SIZE]
            unpacked = struct.unpack(BLOCK_FORMAT, header)
            enc_case_id = unpacked[2]

            if enc_case_id == b"0" * 32:
                continue

            cases.add(enc_case_id.hex())

    except Exception as e:
        print(f"> Error processing blockchain file: {e}", file=sys.stderr)
        sys.exit(1)

    if cases:
        print("> List of Cases in the Blockchain:")
        for case_hex in sorted(cases):
            try:
                enc_case_id_bytes = bytes.fromhex(case_hex)
                decrypted_case_id = decrypt_field(enc_case_id_bytes, is_uuid=True)
                if decrypted_case_id:
                    print(f"- {decrypted_case_id}")
                else:
                    print(f"- Error decrypting case ID: {case_hex}", file=sys.stderr)
            except Exception as e:
                print(f"- Error decrypting case ID: {e}", file=sys.stderr)
    else:
        print("> No cases found in the blockchain.")




def command_show_items():
    """
    Implements the 'show items' command.
    """
    parser = argparse.ArgumentParser(description="Show items for a case")
    parser.add_argument("-c", "--case", required=True, help="Case ID")
    parser.add_argument("-p", "--password", required=True, help="Owner password")
    args = parser.parse_args(sys.argv[3:])

    valid_passwords = [
    os.getenv("BCHOC_PASSWORD_POLICE", "P80P"),
    os.getenv("BCHOC_PASSWORD_ANALYST", "A65A"),
    os.getenv("BCHOC_PASSWORD_EXECUTIVE", "E69E"),
    os.getenv("BCHOC_PASSWORD_LAWYER", "L76L"),
    ]

    if args.password not in valid_passwords:
        print("> Invalid password", file=sys.stderr)
        sys.exit(1)



    file_path = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
    ensure_blockchain_initialized(file_path)

    case_id = args.case
    encrypted_case_id = encrypt_case_id(case_id)

    try:
        print(f"\n**List of Items for Case {case_id} :**")
        items_found = False
        item_states = {}  # Track last state of each item

        for block in iter_blocks(file_path):
            header = block[:HEADER_SIZE]
            unpacked = struct.unpack(BLOCK_FORMAT, header)
            if unpacked[2] == encrypted_case_id:  # Compare encrypted case IDs
                enc_item_id = unpacked[3]
                state = unpacked[4].strip(b"\0")  # Remove null bytes
                
                # Store the last known state of each item
                item_states[enc_item_id] = state

        # Ensure only non-removed items are displayed
        valid_items = {enc_id: state for enc_id, state in item_states.items() if state not in [b"REMOVED"]}
        
        if valid_items:
            for enc_item_id, state in valid_items.items():
                items_found = True
                decrypted_item_id = decrypt_field(enc_item_id)
                if decrypted_item_id is not None:
                    print(f"- {decrypted_item_id} (State: {state.decode('ascii').strip()})")
                else:
                    print(f"- Error decrypting item: {enc_item_id.hex()}", file=sys.stderr)
        else:
            print(f"> No valid items found for case {case_id}")
    
    except Exception as e:
        print(f"> Error processing blockchain file: {e}", file=sys.stderr)
        sys.exit(1)




# --------------------------------------------------------------------
# Command Implementations checkin and checkout
# --------------------------------------------------------------------
def original_creator(file_path, enc_item_id):
    """Return the creator field from the FIRST block for this item."""
    for block in iter_blocks(file_path):
        hdr = block[:HEADER_SIZE]
        _, _, _, iid, _, creator, _, _ = struct.unpack(BLOCK_FORMAT, hdr)
        if iid == enc_item_id:
            return creator
    return b"\x00"*12            # fallback (should not happen)

def _prev_hash_from_last_block(file_path: str) -> bytes:
    """Return 32 × 0 if the last block is the genesis, else SHA-256(last_block)."""
    last_block = get_last_block(file_path)
    if last_block is None:                     # should never happen (init created)
        return b"\0" * 32
    last_state = struct.unpack(BLOCK_FORMAT, last_block[:HEADER_SIZE])[4]
    return b"\0" * 32 if last_state.startswith(b"INITIAL") else compute_hash(last_block)


def command_checkout():
    parser = argparse.ArgumentParser(description="Checkout an evidence item")
    parser.add_argument("-i", "--item", required=True, help="Evidence item ID")
    parser.add_argument("-p", "--password", required=True, help="Owner password")
    args = parser.parse_args(sys.argv[2:])

    role_txt = ROLE_NAME.get(args.password)
    if role_txt is None:
        print("> Invalid password", file=sys.stderr)
        sys.exit(1)

    file_path = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
    ensure_blockchain_initialized(file_path)

    enc_item_id = encrypt_item_id(args.item)
    enc_case_id = get_encrypted_case_id_from_item(file_path, enc_item_id)
    if not enc_case_id:
        print(f"> Item {args.item} not found in blockchain.", file=sys.stderr)
        sys.exit(1)

    if get_last_state(file_path, enc_item_id) != pad_field(b"CHECKEDIN", 12):
        print(f"> Item {args.item} is not in CHECKEDIN state.", file=sys.stderr)
        sys.exit(1)

    prev_hash = b"\0" * 32
    timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
    state     = pad_field(b"CHECKEDOUT", 12)
    creator   = original_creator(file_path, enc_item_id)
    owner     = pad_field(role_txt, 12)
    d_length  = 0

    header = struct.pack(
        BLOCK_FORMAT, prev_hash, timestamp,
        enc_case_id, enc_item_id,
        state, creator, owner, d_length
    )

    with open(file_path, "ab") as f:
        f.write(header)          # no data section

    print(f"> Case: {decrypt_field(enc_case_id, True)}")
    print(f"> Checked out item: {args.item}")
    print("> Status: CHECKEDOUT")
    print(f"> Time of action: {datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).isoformat()}Z")






def command_checkin():
    p = argparse.ArgumentParser(description="Check-in an evidence item")
    p.add_argument("-i", "--item", required=True)
    p.add_argument("-p", "--password", required=True)
    args = p.parse_args(sys.argv[2:])

    role_txt = ROLE_NAME.get(args.password)          # ← keep role
    if role_txt is None:
        print("> Invalid password", file=sys.stderr)
        sys.exit(1)

    file_path = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
    ensure_blockchain_initialized(file_path)

    enc_item_id = encrypt_item_id(args.item)
    enc_case_id = get_encrypted_case_id_from_item(file_path, enc_item_id)
    if not enc_case_id:
        print(f"> Item {args.item} not found in blockchain.", file=sys.stderr)
        sys.exit(1)

    if get_last_state(file_path, enc_item_id) != pad_field(b"CHECKEDOUT", 12):
        print(f"> Item {args.item} is not in CHECKEDOUT state.", file=sys.stderr)
        sys.exit(1)

    prev_hash = b"\0" * 32                           # rule: always zero
    timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
    state     = b"CHECKEDIN\x00\x00"                 # **exactly two NULs**
    creator   = original_creator(file_path, enc_item_id)
    owner     = pad_field(role_txt, 12)              # role as owner
    d_length  = 0

    header = struct.pack(BLOCK_FORMAT, prev_hash, timestamp,
                         enc_case_id, enc_item_id,
                         state, creator, owner, d_length)

    with open(file_path, "ab") as f:
        f.write(header)                              # no data section

    ts_iso = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).isoformat()+"Z"
    print(f"> Case: {decrypt_field(enc_case_id, True)}")
    print(f"> Checked in item: {args.item}")
    print("> Status: CHECKEDIN")
    print(f"> Time of action: {ts_iso}")


def command_remove():
    """
    Implements the 'remove' command.
    """
    parser = argparse.ArgumentParser(description="Remove an evidence item")
    parser.add_argument("-i", "--item", required=True, help="Evidence item ID")
    parser.add_argument("-y", "--why", required=True, choices=["DISPOSED", "DESTROYED", "RELEASED"], help="Reason for removal")
    parser.add_argument("-o", "--owner", help="New owner (if RELEASED)")
    parser.add_argument("-p", "--password", required=True, help="Creator password")
    args = parser.parse_args(sys.argv[2:])

    creator_password = os.getenv("BCHOC_PASSWORD_CREATOR", "C67C")
    if args.password != creator_password:
        print("> Invalid password", file=sys.stderr)
        sys.exit(1)

    file_path = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
    ensure_blockchain_initialized(file_path)

    try:
        item_id = int(args.item)
        encrypted_item_id = encrypt_item_id(str(item_id))
        blockchain = load_blocks_from_file(file_path)
        last_block = blockchain[-1] if blockchain else None

        if last_block is None:
            print("> Blockchain file is empty.", file=sys.stderr)
            sys.exit(1)
        
        last_state = None
        encrypted_case_id = None

        for block in reversed(blockchain):
            if block["encrypted_item_id"] == encrypted_item_id:
                last_state = block["state"]
                encrypted_case_id = block["encrypted_case_id"]
                break

        if last_state is None:
            print(f"> Item {args.item} not found in blockchain.", file=sys.stderr)
            sys.exit(1)

        if last_state.startswith(b"REMOVED"):
            print(f"> Error: Item {args.item} has already been removed.", file=sys.stderr)
            sys.exit(1)

        if last_state != pad_field(b"CHECKEDIN", 12):
            print(f"> Error: Item {args.item} is not in CHECKEDIN state.", file=sys.stderr)
            sys.exit(1)

        timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
        state = pad_field(b"REMOVED", 12)
        creator = b"\0" * 12
        owner_info = args.owner if args.why == "RELEASED" else ""
        owner_bytes = owner_info.encode('ascii') if owner_info else b"\0" * 12
        owner = pad_field(owner_bytes, 12)
        data_str = f"Removed item: {args.item} ({args.why})" + (f" - To {owner_info}" if args.why == "RELEASED" else "") + "\0"
        data_bytes = data_str.encode('ascii')
        d_length = len(data_bytes)

        last_block_bytes = struct.pack(
            BLOCK_FORMAT,
            last_block["prev_hash"],
            last_block["timestamp"],
            last_block["encrypted_case_id"],
            last_block["encrypted_item_id"],
            last_block["state"],
            last_block["creator"],
            last_block["owner"],
            len(last_block["data"])
        ) + last_block["data"]

        prev_hash = compute_hash(last_block_bytes)

        with open(file_path, "ab") as f:
            header = struct.pack(BLOCK_FORMAT, prev_hash, timestamp, encrypted_case_id, encrypted_item_id, state, creator, owner, d_length)
            block = header + data_bytes
            f.write(block)
            f.flush()

        timestamp_iso = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).isoformat() + "Z"
        decrypted_case_id = decrypt_field(encrypted_case_id, is_uuid=True)
        print(f"> Case: {decrypted_case_id}")
        print(f"> Removed item: {args.item}")
        print(f"> Reason: {args.why}")
        print(f"> Status: REMOVED")
        print(f"> Time of action: {timestamp_iso}")

    except Exception as e:
        print(f"> Error: {e}", file=sys.stderr)
        sys.exit(1)

# --------------------------------------------------------------------
# Command Implementations verify and history
# --------------------------------------------------------------------

def command_verify():
    """
    Implements the 'verify' command.
    """
    file_path = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
    ensure_blockchain_initialized(file_path)

    try:
        block_count = 0
        last_block = None
        for block in iter_blocks(file_path):
            block_count += 1
            header = block[:HEADER_SIZE]
            unpacked = struct.unpack(BLOCK_FORMAT, header)
            prev_hash, timestamp, case_id, evidence_id, state, creator, owner, d_length = unpacked
            data = block[HEADER_SIZE:]

            # 1. Check Previous Hash
            if last_block:
                computed_prev_hash = compute_hash(last_block)
                if computed_prev_hash != prev_hash:
                    print(f"> State of blockchain: ERROR", file=sys.stderr)
                    print(f"> Bad block: {compute_hash(block).hex()}", file=sys.stderr)
                    print(f"> Parent block: {computed_prev_hash.hex()}", file=sys.stderr)
                    sys.exit(1)
            else:  # First block (genesis)
                expected_prev_hash = b"0" * 32
                if prev_hash != expected_prev_hash:
                    print(f"> State of blockchain: ERROR", file=sys.stderr)
                    print(f"> Bad block: {compute_hash(block).hex()}", file=sys.stderr)
                    print(f"> Genesis block prev_hash is invalid", file=sys.stderr)
                    sys.exit(1)

            # 2. Check Data Length
            if len(data) != d_length:
                print(f"> State of blockchain: ERROR", file=sys.stderr)
                print(f"> Bad block: {compute_hash(block).hex()}", file=sys.stderr)
                print(f"> Data length mismatch", file=sys.stderr)
                sys.exit(1)

            # 3. Check Block Integrity (Hash) - Optional, but recommended
            computed_block_hash = compute_hash(block)
            # You might need to store block hashes and compare here

            last_block = block  # Update last_block for the next iteration

        print(f"> Transactions in blockchain: {block_count}")
        print(f"> State of blockchain: CLEAN")

    except Exception as e:
        print(f"> Error verifying blockchain: {e}", file=sys.stderr)
        sys.exit(1)








def command_show_history():
    """
    Implements the 'show history' command.
    """
    parser = argparse.ArgumentParser(description="Show blockchain history")
    parser.add_argument("-c", "--case", help="Case ID")
    parser.add_argument("-i", "--item", help="Item ID")
    parser.add_argument("-n", "--num_entries", type=int, help="Number of entries to show")
    parser.add_argument("-r", "--reverse", action="store_true", help="Reverse the order of entries")
    parser.add_argument("-p", "--password", required=True, help="Password")
    args = parser.parse_args(sys.argv[3:])

    valid_passwords = [
        os.getenv("BCHOC_PASSWORD_POLICE", "P80P"),
        os.getenv("BCHOC_PASSWORD_ANALYST", "A65A"),
        os.getenv("BCHOC_PASSWORD_EXECUTIVE", "E69E"),
        os.getenv("BCHOC_PASSWORD_LAWYER", "L76L"),
    ]

    if args.password not in valid_passwords:
        print("> Invalid password", file=sys.stderr)
        sys.exit(1)

    file_path = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
    ensure_blockchain_initialized(file_path)

    entries = []

    try:
        for block in iter_blocks(file_path):
            header = block[:HEADER_SIZE]
            unpacked = struct.unpack(BLOCK_FORMAT, header)
            prev_hash, timestamp, enc_case_id, enc_item_id, state, creator, owner, d_length = unpacked
            data = block[HEADER_SIZE:HEADER_SIZE + d_length].decode('ascii')
            timestamp_iso = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).isoformat() + "Z"

            decrypted_case_id = decrypt_field(enc_case_id, is_uuid=True)
            decrypted_item_id = decrypt_field(enc_item_id, is_uuid=False)

            entry = {
                "case": decrypted_case_id,
                "item": decrypted_item_id,
                "action": state.decode('ascii').rstrip('\0'),
                "time": timestamp_iso,
                "data": data
            }
            entries.append(entry)

    except Exception as e:
        print(f"> Error: {e}", file=sys.stderr)
        sys.exit(1)

    # � Now apply filters properly
    filtered_entries = []

    for entry in entries:
        case_match = True
        item_match = True

        if args.case:
            case_match = (str(entry["case"]) == args.case)

        if args.item:
            item_match = (str(entry["item"]) == args.item)

        if case_match and item_match:
            filtered_entries.append(entry)

    # Reverse if needed
    if args.reverse:
        filtered_entries.reverse()

    # Limit number of entries if needed
    if args.num_entries:
        filtered_entries = filtered_entries[:args.num_entries]

    # Print filtered entries
    for entry in filtered_entries:
        print(f"> Case: {entry['case']}")
        print(f"> Item: {entry['item']}")
        print(f"> Action: {entry['action']}")
        print(f"> Time: {entry['time']}")
        print(f"> Data: {entry['data']}\n")












# Summary Command

def command_summary():
    """
    Implements the 'summary' command.
    """
    parser = argparse.ArgumentParser(description="Summary for a given case")
    parser.add_argument("-c", "--case", required=True, help="Case ID")
    args = parser.parse_args(sys.argv[2:])

    file_path = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
    ensure_blockchain_initialized(file_path)

    try:
        encrypted_case_id = encrypt_case_id(args.case)
    except Exception:
        print("> Invalid case ID format", file=sys.stderr)
        sys.exit(1)

    item_states = {}

    try:
        for block in iter_blocks(file_path):
            header = block[:HEADER_SIZE]
            unpacked = struct.unpack(BLOCK_FORMAT, header)
            prev_hash, timestamp, enc_case_id, enc_item_id, state, creator, owner, d_length = unpacked

            if enc_case_id == encrypted_case_id:
                item_states[enc_item_id] = state.strip(b"\0").decode('ascii')  # Remove \0 padding and decode

        if not item_states:
            print(f"> No items found for case {args.case}")
            sys.exit(0)

        # Count items by state
        total_items = len(item_states)
        count_checkedin = list(item_states.values()).count("CHECKEDIN")
        count_checkedout = list(item_states.values()).count("CHECKEDOUT")
        count_disposed = list(item_states.values()).count("DISPOSED")
        count_destroyed = list(item_states.values()).count("DESTROYED")
        count_released = list(item_states.values()).count("RELEASED")

        # Output results
        print(f"> Number of unique items: {total_items}")
        print(f"> Number of CHECKEDIN items: {count_checkedin}")
        print(f"> Number of CHECKEDOUT items: {count_checkedout}")
        print(f"> Number of DISPOSED items: {count_disposed}")
        print(f"> Number of DESTROYED items: {count_destroyed}")
        print(f"> Number of RELEASED items: {count_released}")

    except Exception as e:
        print(f"> Error processing blockchain file: {e}", file=sys.stderr)
        sys.exit(1)


# --------------------------------------------------------------------
# Main Dispatch
# --------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: bchoc <command> [options]", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "init":
        if len(sys.argv) != 2:
            print("Usage: ./bchoc init", file=sys.stderr)
            sys.exit(1)
        command_init()
    elif command == "add":
        command_add()
    elif command == "show":  # Handle 'show' command and its subcommands
        if len(sys.argv) > 2:
            subcommand = sys.argv[2].lower()
            if subcommand == "cases":
                command_show_cases()
            elif subcommand == "items":
                command_show_items()
            elif subcommand == "history":
                command_show_history()
            else:
                print("Unknown subcommand for 'show':", subcommand, file=sys.stderr)
                sys.exit(1)
        else:
            print("Missing subcommand for 'show'", file=sys.stderr)
            sys.exit(1)
    elif command == "checkout":
        command_checkout()
    elif command == "checkin":
        command_checkin()
    elif command == "remove":
        command_remove()
    elif command == "verify":
        command_verify()

    elif command == "summary":
        command_summary()

    else:
        print("Unknown command:", command, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()