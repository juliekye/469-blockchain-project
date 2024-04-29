#!/usr/bin/env python3

import argparse
from copy import deepcopy
import hashlib
import os
import traceback
import uuid
import maya
import struct

from enum import Enum
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from constants import AES_KEY, BCHOC_FILE_PATH, BCHOC_PASSWORD_CREATOR, Owner, get_owner, is_valid_password





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
        self.data = "Initial block\x00"
        
        self.password: str = None
        self.byte_data: bytes = self._to_bytes()

    @classmethod
    def from_bytes(cls, byte_data: bytes):
        block_instance = cls()
        block_instance.byte_data = byte_data
        
        fields = struct.unpack('32s d 32s 32s 12s 12s 12s I', byte_data[:144])  # Unpacking till Data Length
        block_instance.sha_256_hash = fields[0].hex() if fields[0] != b'\x00' * 32 else None
        block_instance.time = maya.MayaDT(fields[1]) if fields[1] != b'\x00' * 8 else None
        block_instance.case_uuid = uuid.UUID(bytes=cls.decrypt_data(fields[2])) if fields[2] != b'\x00' * 32 else None
        block_instance.evidence_item_id = int.from_bytes(fields[3], byteorder='little', signed=False) if fields[3] != b'\x00' * 32 else None
        block_instance.state = BlockState.from_name(fields[4].decode('utf-8').strip('\x00'))
        block_instance.creator = fields[5].decode('utf-8').strip('\x00') if fields[5] != b'\x00' * 12 else None
        block_instance.owner = Owner(fields[6].decode('utf-8').strip('\x00')) if fields[6] != b'\x00' * 12 else None
        block_instance.data_length = fields[7]
        block_instance.data = byte_data[144:144 + block_instance.data_length].decode('utf-8')
        
        return block_instance
    
    def __len__(self) -> int:
        return 144 + self.data_length

    def _to_bytes(self) -> bytes:
        # Before packing, ensure that all None fields are appropriately handled.
        # For UUID and hashes, convert to bytes, for others use empty strings.
        byte_data = struct.pack(
            '32s d 32s 32s 12s 12s 12s I',
            (self.sha_256_hash.encode('utf-8') if isinstance(self.sha_256_hash, str) else self.sha_256_hash) if self.sha_256_hash else b'\x00' * 32,
            self.time.epoch if self.time else 0,
            self.encrypt_data(self.case_uuid.bytes) if self.case_uuid else b'\x00' * 32,
            self.evidence_item_id.to_bytes(32, byteorder='little', signed=False) if self.evidence_item_id else b'\x00' * 32,
            self.state.name.encode('utf-8').ljust(12, b'\x00'),
            self.creator.encode('utf-8').ljust(12, b'\x00') if self.creator else b'\x00' * 12,
            self.owner.name.encode('utf-8').ljust(12, b'\x00') if self.owner else b'\x00' * 12,
            self.data_length
        )
        byte_data += self.data.encode('utf-8')  
        return byte_data
    
    def refresh(self):
        """Every time a data is refreshed - this method shuold be called"""
        self.byte_data = self._to_bytes()

    def to_bytes(self):
        return self.byte_data

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
    
    def compute_hash(self) -> bytes:
        """
        Generates sha256 hash of a given block, returns bytes
        """
        return hashlib.sha256(self.to_bytes()).digest()
    
    def get_encrypted_uuid(self):
        return self.encrypt_data(self.case_uuid.bytes).hex()
    

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

    def add(self, case_id, item_ids, creator, password):
        # Verify data
        if not case_id or not item_ids or not creator or not password:
            print('Wrong parameters passed to add!')
            exit(1)

        # Verify password
        if password.encode('utf-8') != BCHOC_PASSWORD_CREATOR:
            print('Invalid password')
            exit(1)

        # Make sure all item id's are unique
        if any(b.evidence_item_id == i_id for b in self.blocks for i_id in item_ids):
            print('All item ids must be unique!')
            exit(1)

        # Duplicates in item_ids
        if len(set(item_ids)) != len(item_ids):
            print('Duplicate item ids received!')
            exit(1)

        # Add new blocks
        for i_id in item_ids:
            b = Block()
            b.sha_256_hash = self.blocks[-1].compute_hash()
            b.password = password
            b.case_uuid = uuid.UUID(case_id)
            b.evidence_item_id = i_id
            b.state = BlockState.CHECKEDIN
            b.creator = creator
            b.data = "No data"
            b.data_length = len(b.data)
            b.refresh()
            self.blocks.append(b)
            print(f'Case: {b.case_uuid}\nItem: {b.evidence_item_id}\nAction: CHECKEDIN\nTime: {b.time.iso8601()}')

        self._save()

    def remove(self, item_id: int, reason: str, password: str):
        # Verify data
        if not item_id or not reason or not password:
            print('Wrong parameters passed to remove!')
            exit(1)
        
        # Verify reason
        if reason not in ['DISPOSED', 'DESTROYED', 'RELEASED']:
            print('invalid reason')
            exit(1)

        # Verify password
        if password.encode('utf-8') != BCHOC_PASSWORD_CREATOR:
            print('Invalid password')
            exit(1)

        if all(b.evidence_item_id != item_id for b in self.blocks):
            print('Item id does not exist!')
            exit(1)

        for b in self.blocks[::-1]:
            if b.evidence_item_id == item_id:
                if b.state != BlockState.CHECKEDIN:
                    print('Block must be checked in!')
                    exit(1)
                new_b = deepcopy(b)
                new_b.state = BlockState.DESTROYED
                new_b.owner = get_owner(password)
                new_b.time = maya.now()
                new_b.data = f'Removed. Reason: {reason}'
                new_b.data_length = len(new_b.data)
                new_b.sha_256_hash = self.blocks[-1].compute_hash()
                new_b.refresh()
                self.blocks.append(new_b)
                self._save()
                return print(f'Removed item: {item_id}\nStatus: DESTROYED\nTime of action: {new_b.time.iso8601()}')
            

    def checkin(self, item_id, password):
        if not item_id or not password:
            print('Wrong parameters passed to add!')
            exit(1)
        if not is_valid_password(password):
            print('Invalid password')
            exit(1)
        for b in self.blocks[::-1]:
            if item_id == b.evidence_item_id:
                if b.state == BlockState.CHECKEDIN:
                    return print('Item is already checked in!')
                if b.state != BlockState.CHECKEDOUT:
                    print('Item must be checked in!')
                    exit(1)
                #if b.owner != get_owner(password):
                #    print('Invalid password')
                #    exit(1)

                new_b = deepcopy(b)
                new_b.state = BlockState.CHECKEDIN
                new_b.owner = None
                new_b.time = maya.now()
                new_b.refresh()
                self.blocks.append(new_b)
                self._save()
                
                print(f'Case: {b.case_uuid}\nChecked in item: {item_id}\nStatus: CHECKEDIN\nTime of action: {new_b.time.iso8601()}')
                return
        print('Item with given id not found!')
        exit(1)
    
    def checkout(self, item_id, password):
        if not item_id or not password:
            print('Wrong parameters passed to add!')
            exit(1)
        if not is_valid_password(password):
            print('Invalid password')
            exit(1)
        for b in self.blocks[::-1]:
            if item_id == b.evidence_item_id:
                if b.state == BlockState.CHECKEDOUT:
                    return print('Item is already checked out!')
                    exit(1)
                if b.state != BlockState.CHECKEDIN:
                    print('Item must be checked in!')
                    exit(1)

                new_b = deepcopy(b)
                new_b.state = BlockState.CHECKEDOUT
                new_b.owner = get_owner(password)
                new_b.time = maya.now()
                new_b.refresh()
                self.blocks.append(new_b)
                self._save()
                
                print(f'Case: {b.case_uuid}\nChecked out item: {item_id}\nStatus: CHECKEDOUT\nTime of action: {new_b.time.iso8601()}')
                return
        print('Item with given id not found!')
        exit(1)

    def show_cases(self):
        unique_cases = []
        for block in self.blocks:
            if block.case_uuid and block.case_uuid != "None":
                if not block.case_uuid in unique_cases:
                    unique_cases.append(block.case_uuid) 

        if unique_cases:
            for case in unique_cases[::-1]:
                print(case)  
        else:
            print("No cases found in the blockchain.")
    
    def show_items(self, case_id):
        case_items = []
        for block in self.blocks:
            if block.case_uuid == uuid.UUID(case_id) and not block.evidence_item_id in case_items:
                case_items.append(block.evidence_item_id)

        if case_items:
            for item in case_items[::-1]:
                print(item)
        else:
            print("No items found for this case")

    def show_history(self, case_id, item_id, num_entries, reverse, password):
        if password and not is_valid_password(password):
            print('Invalid password')
            exit(1)
        block_history = []
        if case_id:
            for b in self.blocks:
                if b.case_uuid == case_id:
                    block_history.append(b)
        elif item_id: 
            for b in self.blocks:
                if b.evidence_item_id == item_id:
                    block_history.append(b)
        if num_entries:
            block_history = block_history[:num_entries]
        if reverse:
            block_history = block_history[::-1]
        for b in block_history:
            if not password:
                print(f'Case: {b.get_encrypted_uuid()}\nItem: {b.evidence_item_id}\nAction: {b.state.name}\nTime: {b.time.iso8601()}')
            else:
                print(f'Case: {b.case_uuid}\nItem: {b.evidence_item_id}\nAction: {b.state.name}\nTime: {b.time.iso8601()}')


def parse_command_line():
    parser = argparse.ArgumentParser(description="Blockchain Command Line Interface")

    # Create a subparsers object for handling subcommands
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    # Parser for init
    parser_init = subparsers.add_parser('init', help='Initializes blockchain')

    # Parser for the 'add' command
    parser_add = subparsers.add_parser('add', help='add a new item to the blockchain')
    parser_add.add_argument('-c', '--case_id', required=True, help='Case ID')
    parser_add.add_argument('-i', '--item_id', action='append', type=int, required=True, help='Item ID(s)')
    parser_add.add_argument('-g', '--creator', required=True, help="Creator's name")
    parser_add.add_argument('-p', '--password', help="Creator's password")

    # Parser for the 'checkin' command
    parser_checkin = subparsers.add_parser('checkin')
    parser_checkin.add_argument('-i', '--item_id', type=int)
    parser_checkin.add_argument('-p', '--password')

    # Parser for the 'checkout' command
    parser_checkin = subparsers.add_parser('checkout')
    parser_checkin.add_argument('-i', '--item_id', type=int)
    parser_checkin.add_argument('-p', '--password')


    # Parser for the 'remove' command
    parser_remove = subparsers.add_parser('remove', help='Removes an item')
    parser_remove.add_argument('-i', '--item_id', type=int, required=True, help='Item ID')
    #parser_remove.add_argument('-y', '--reason', help="Reason for removing an item")
    parser_remove.add_argument('-y', '--why', required=True, dest='reason', help="Reason for removing an item")
    parser_remove.add_argument('-p', '--password', help="Creator's Password")

    #parser for 'show cases' 'show items' and 'show history' commands
    parser_show = subparsers.add_parser('show', help='Show commands')
    show_subparsers = parser_show.add_subparsers(dest='show_command', required=True, help='Show specific details')

    #parser for show cases
    show_subparsers.add_parser('cases', help='Show all cases')

    #parser for show items
    parser_show_items = show_subparsers.add_parser('items', help='Show all items')
    parser_show_items.add_argument('-c', '--case_id', help="Case ID", type=str)

    #parser for show history
    parser_history = show_subparsers.add_parser('history', help='Show the history of a case or an item')
    parser_history.add_argument('-c', '--case_id', help="Case ID", type=str)
    parser_history.add_argument('-i', '--item_id', help="Item ID", type=int)
    parser_history.add_argument('-n', '--num_entries', type=int, help="Number of entries to show")
    parser_history.add_argument('-r', '--reverse', action='store_true', help="Reverse the order of entries")
    parser_history.add_argument('-p', '--password', help="password")

    # Parse the command line arguments
    args = parser.parse_args()

    blockchain = BlockChain()
    msg = blockchain.init_blockchain()

    # Call the appropriate handler based on the command
    if args.command == 'init':
        print(msg)
    elif args.command == 'verify':
        # blockchain.verify()
        pass
    elif args.command == 'add':
        if msg == 'Blockchain file not found. Created INITIAL block.': print(msg)
        blockchain.add(args.case_id, args.item_id, args.creator, args.password)
    elif args.command == 'checkin':
        blockchain.checkin(args.item_id, args.password)
    elif args.command == 'checkout':
        blockchain.checkout(args.item_id, args.password)
    elif args.command == 'remove':
        blockchain.remove(args.item_id, args.reason, args.password)
    elif args.command == 'show':
        if args.show_command == 'cases':
            blockchain.show_cases()
        elif args.show_command == 'items':
            blockchain.show_items(args.case_id)
        elif args.show_command == 'history':
            blockchain.show_history(args.case_id, args.item_id, args.num_entries, args.reverse, args.password)
       
    else:
        parser.print_help()



if __name__ == '__main__':
    parse_command_line()
