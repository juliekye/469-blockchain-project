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

    @classmethod
    def from_bytes(cls, byte_data: bytes):
        block_instance = cls()
        
        fields = struct.unpack('32s d 32s 32s 12s 12s 12s I', byte_data[:144])  # Unpacking till Data Length
        block_instance.sha_256_hash = fields[0].hex() if fields[0] != b'\x00' * 32 else None
        block_instance.time = maya.MayaDT(fields[1])
        block_instance.case_uuid = uuid.UUID(bytes=fields[2]) if fields[2] != b'\x00' * 32 else None
        block_instance.evidence_item_id = fields[3] if fields[3] != b'\x00' * 32 else None
        block_instance.state = BlockState.from_name(fields[4].decode('utf-8').strip('\x00'))
        block_instance.creator = fields[5].decode('utf-8').strip('\x00') if fields[5] != b'\x00' * 12 else None
        block_instance.owner = Owner(fields[6].decode('utf-8').strip('\x00')) if fields[6] != b'\x00' * 12 else None
        block_instance.data_length = fields[7]
        block_instance.data = byte_data[144:144 + block_instance.data_length].decode('utf-8')
        
        return block_instance
    
    def __len__(self) -> int:
        return 144 + self.data_length


    def to_bytes(self) -> bytes:
        # handle None fields before packing 
        # For UUID and hashes, convert to bytes, for others use empty strings.
        byte_data = struct.pack(
            '32s d 32s 32s 12s 12s 12s I',
            bytes.fromhex(self.sha_256_hash) if self.sha_256_hash else b'\x00' * 32,
            self.time.epoch,
            self.case_uuid.bytes if self.case_uuid else b'\x00' * 32,
            self.encrypt_data(str(self.evidence_item_id).encode('utf-8')) if self.evidence_item_id else b'\x00' * 32,
            self.state.name.encode('utf-8').ljust(12, b'\x00'),
            self.creator.encode('utf-8').ljust(12, b'\x00') if self.creator else b'\x00' * 12,
            self.owner.name.encode('utf-8').ljust(12, b'\x00') if self.owner else b'\x00' * 12,
            self.data_length
        )
        byte_data += self.data.encode('utf-8')  
        return byte_data

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

    def init_blockchain(self) -> str:
        if os.path.exists(self.path):
            self._read()
            return 'Blockchain file found with INITIAL block.'
        else:
            self.blocks.append(Block())
            self._save()
            return 'Blockchain file not found. Created INITIAL block.'
        

    def verify(self) -> str:
        Txs = 0
        observed_hashes = []
        expected_hashes = []
        for b in self.blocks:
            Txs += 1
            observed_hashes.append(hashlib.sha256(b.to_bytes()).hexdigest())
            expected_hashes.append(b.sha_256_hash)

        print(f'Transactions in blockchain: {Txs}')
        
        
        
    def _read(self):
        with open(self.path, 'rb') as f:
            data = f.read() # read all bytes
        
        while data:
            b = Block.from_bytes(data)
            self.blocks.append(b)
            data = data[len(b):]
    

    def _save(self):
        bytes_data = b''.join(map(lambda b: b.to_bytes(), self.blocks)) # convert to bytes
        with open(self.path, 'wb') as f:
            f.write(bytes_data)




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
        print(blockchain.init_blockchain())
    elif args.command == 'verify':
        # blockchain.verify()
        pass
    elif args.command == 'add':
        handle_add(args.case_id, args.item_id, args.creator, password)
    else:
        parser.print_help()


if __name__ == '__main__':
    parse_command_line()
