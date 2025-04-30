Team Number 19:
Authors Team:

Ayran
Connor
Raejae
Sam


# BCHOC - Blockchain Chain of Custody

## Overview

BCHOC is a blockchain-based chain of custody system for tracking evidence items. It ensures secure storage, tracking, and access to case-related evidence.

## Installation

### Prerequisites

- Python 3.x
- Required dependencies: `pycryptodome`

### Install Dependencies

```sh
pip install pycryptodome
```



### Set environment variables (Example):

export BCHOC_PASSWORD_OWNER="ownerpass"
export BCHOC_PASSWORD_CREATOR="C67C"
export BCHOC_PASSWORD_ANALYST="A65A"
export BCHOC_PASSWORD_POLICE="P80P"


## Usage

1. ### Initialize the Blockchain

To initialize the blockchain, run:

```sh
./bchoc.py init
```

2. ### Adding Evidence

To add an evidence item to the blockchain:

```sh
./bchoc.py add -c <case_id> -i <item_id> -g <creator> -p <password>
```

Example:

```sh
./bchoc.py add -c 123e4567-e89b-12d3-a456-426614174000 -i 1001 -g creator -p C67C
```


3. ### Verify Blockchain Integrity
```sh 
./bchoc.py verify
````

### Show all cases

```sh
./bchoc.py show cases -p <owner_password>
```

Example:

```sh
./bchoc.py show cases -p ownerpass
```

4. ### Viewing Items in a Case

```sh
./bchoc.py show items -c <case_id> -p <owner_password>
```

Example:

```sh
./bchoc.py show items -c 123e4567-e89b-12d3-a456-426614174000 -p ownerpass
```

5. ### Checkout an Item

```sh
./bchoc.py checkout -i <item_id> -p <police_password>
```

Example:

```sh
./bchoc.py checkout -i 1001 -p P80P
```

6. ### Checkin an Item

```sh
./bchoc.py checkin -i <item_id> -p <analyst_password>
```

Example:

```sh
./bchoc.py checkin -i 1001 -p A65A
```

7. ### Removing an Item

```sh
./bchoc.py remove -i <item_id> -y <reason> -p <creator_password>
```

Reasons: `DISPOSED`, `DESTROYED`, `RELEASED`

Example:

```sh
./bchoc.py remove -i 1001 -y DISPOSED -p C67C
```

8. ### Viewing History

```sh
./bchoc.py show history -c <case_id> -p <owner_password>
```

Example:

```sh
./bchoc.py show history -c 123e4567-e89b-12d3-a456-426614174000 -p ownerpass
```

9. ### Verify Blockchain Integrity

```sh
./bchoc.py verify
```

This checks if the blockchain is valid.


10. ### Check Blockchain Record in Hex: 
``` sh
xxd blockchain.dat | less
```

### To get both hexadecimal and ASCII output:
    ```sh
    hexdump -C blockchain.dat | less
    ```
    The file stored inside blockchain.dat as binary
    if you want to stored the data differen file type any FileName on terminal you will seee the recored hex data.

## Automated Testing

A test script `test_bchoc.sh` is included to automate the testing of core functionality.

Run the test:

```sh
bash test_bchoc.sh
```


