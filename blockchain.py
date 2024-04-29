import argparse
import hashlib
import os
import traceback
import uuid
import maya
import struct

from enum import Enum
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from constants import AES_KEY, BCHOC_FILE_PATH


class Owner(Enum):
    POLICE = 0
    LAWYER = 1
    ANALYST = 2
    EXECUTIVE = 3


class BlockState(Enum):
    @staticmethod
    def from_name(name: str):
        m = {'INITIAL': BlockState.INITIAL, 'CHECKEDIN': BlockState.CHECKEDIN, 'CHECKEDOUT': BlockState.CHECKEDOUT,
              'DISPOSED': BlockState.DISPOSED, 'DESTROYED': BlockState.DESTROYED, 'RELEASED': BlockState.RELEASED}
        return m.get(name, None)

    INITIAL = 'INITIAL'
    CHECKEDIN = 'CHECKEDIN'
    CHECKEDOUT = 'CHECKEDOUT'
    DISPOSED = 'DISPOSED'
    DESTROYED = 'DESTROYED'
    RELEASED = 'RELEASED'


class Block:
    def __init__(self) -> None:
        self.sha_256_hash = None
        self.time = maya.now()
        self.case_uuid = None
        self.evidence_item_id = None
        self.state = BlockState.INITIAL
        self.creator = None
        self.owner = None
        self.data_length = 14
        self.data = "Initial block"

    def calculate_hash(self):
        hash_data = str(self.time) + str(self.case_uuid) + str(self.evidence_item_id) + \
                    self.state.value + self.creator + self.owner.value + self.data
        self.sha_256_hash = hashlib.sha256(hash_data.encode()).hexdigest()

    def __len__(self) -> int:
        return 144 + self.data_length


    @staticmethod
    def encrypt_data(data: bytes) -> bytes:
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        return encrypted_data

    @staticmethod
    def decrypt_data(encrypted_data: bytes) -> bytes:
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted_data
    

class BlockChain:
    def __init__(self, path: str = BCHOC_FILE_PATH):
        self.path = path
        self.blocks: list[Block] = []
        self.init_blockchain()

    def init_blockchain(self):
        if not os.path.exists(self.path):
            # Create the initial block
            initial_block = Block()
            initial_block.calculate_hash()
            self.blocks.append(initial_block)
            self.save()
            print("Blockchain initialized with INITIAL block.")
        else:
            print("Blockchain already initialized.")
            self.load()

    def save(self):
        with open(self.path, 'w') as f:
            for block in self.blocks:
                f.write(f"{block.__dict__}\n")  # Simplified storage format

    def load(self):
        with open(self.path, 'r') as f:
            for line in f:
                block_data = eval(line.strip())
                block = Block()
                block.__dict__.update(block_data)
                self.blocks.append(block)


def parse_command_line():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command', help='sub-command help')

    # Parser for 'init' command
    subparsers.add_parser('init', help='initialize the blockchain')

    # Parser for 'verify' command
    subparsers.add_parser('verify', help='verify the blockchain')

    # Parser for 'add' command
    parser_add = subparsers.add_parser('add', help='add a new item to the blockchain')
    parser_add.add_argument('-c', '--case_id', required=True, help='Case ID')
    parser_add.add_argument('-i', '--item_id', action='append', type=int, required=True, help='Item ID(s)')
    parser_add.add_argument('-o', '--creator', required=True, help="Creator's name")
    parser_add.add_argument('-p', '--password', help="Creator's password")

    args = parser.parse_args()

    blockchain = BlockChain()

    # Call the appropriate handler based on the command
    if args.command == 'init':
        message = blockchain.init_blockchain()
        print(message)
    elif args.command == 'verify':
        # blockchain.verify()
        pass
    elif args.command == 'add':
        #password = args.password if args.password else getpass('Password:')
        handle_add(args.case_id, args.item_id, args.creator, args.password)
    else:
        parser.print_help()


if __name__ == '__main__':
    parse_command_line()
