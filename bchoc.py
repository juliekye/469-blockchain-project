#!/usr/bin/env python3

import sys
import os
import os.path

import uuid
import argparse
import struct
import hashlib
from enum import Enum, auto
from datetime import datetime

class BlockState(Enum):
	INITIAL = auto()
	CHECKEDIN = auto()
	CHECKEDOUT = auto()
	DISPOSED = auto()
	DESTROYED = auto()
	RELEASED = auto()
	
	def pack(self):
		bs = self.name.encode()
		return bs + b'\x00' * (12 - len(bs))
	
	@staticmethod
	def unpack(bs):
		return BlockState.fromStr(bs[:bs.find(b'\x00')].decode().upper())
	
	@staticmethod
	def fromStr(s):
		if s == 'RELEESED':
			s = 'RELEASED'
		
		return BlockState[s.upper()]
	
	@staticmethod
	def fromReason(reason):
		state = BlockState.fromStr(reason)
		if not state.isRemoved():
			raise ValueError("Reason must be one of DISPOSED, DESTROYED, or RELEASED")
		return state
	
	def isRemoved(self):
		""" Check if this state is one in which the item is removed """
		return self in [BlockState.DISPOSED, BlockState.DESTROYED, BlockState.RELEASED]
	
	
	def __str__(self):
		return self.name

class Block:
	def __init__(self,
		case_id, item_id,
		state=BlockState.CHECKEDIN,
		prev_hash=20 * b'\x00',
		data=b'', time=None
	):
		self.prev_hash = prev_hash
		self.time = datetime.now() if time is None else time
		self.case_id = case_id
		self.state = state
		self.item_id = item_id
		self.data = data
	
	def hash(self):
		return hashlib.sha1(self.pack()).digest()
	
	
	# Struct format used to pack and unpack Blocks
	STRUCT = struct.Struct("20s xxxx d 16s I 12s I")
	
	def packsize(self):
		""" Number of bytes in packed representation """
		return Block.STRUCT.size + len(self.data)
	
	def pack(self):
		""" Generate packed binary representation of block """
		return Block.STRUCT.pack(
			self.prev_hash,
			self.time.timestamp(),
			bytes(reversed(self.case_id.bytes)),
			self.item_id,
			self.state.pack(),
			len(self.data)
		) + self.data
	
	@staticmethod
	def unpack(bts):
		""" Create block from binary """
		# Check that there is enough content
		if len(bts) < Block.STRUCT.size:
			return None
		
		(   # Unpack fixed size fields
			prev_hash,
			timestamp,
			case_id,
			item_id,
			state,
			data_len
		) = Block.STRUCT.unpack(bts[:Block.STRUCT.size])
		data = bts[Block.STRUCT.size:][:data_len]
		
		return Block(uuid.UUID(bytes=bytes(reversed(case_id))), item_id,
			state=BlockState.unpack(state),
			data=data,
			prev_hash=prev_hash,
			time=datetime.fromtimestamp(timestamp)
		)
	
	
	def __str__(self):
		return ("Case: %s\nItem: %i\nAction: %s\nTime: %sZ\n"
			% (self.case_id, self.item_id, self.state, self.time.isoformat()))

class Blockchain:
	def __init__(self, blocks=None):
		if blocks is None or len(blocks) == 0:
			# Create initial block
			self.blocks = [Block(
				uuid.UUID(int=0), 0,
				data=b'Initial block\x00', state=BlockState.INITIAL
			)]
		else:
			self.blocks = blocks
	
	def pack(self):
		return b''.join(blk.pack() for blk in self.blocks)
	
	@staticmethod
	def unpack(bts):
		# Remove successive blocks from bytes
		blocks = []
		while len(bts) > 0:
			try:
				blk = Block.unpack(bts)
				if blk is None:
					return None
				
				bts = bts[blk.packsize():]  # Cut off used bytes
			except IndexError:
				raise EOFError("Incorrectly formatted Blockchain file")
			
			blocks.append(blk)
		return Blockchain(blocks)
	
	def __getitem__(self, key):
		if isinstance(key, uuid.UUID):  # When key is a case_id return set of item_ids
			return set(blk.item_id for blk in self.blocks[1:] if blk.case_id == key)
		elif type(key) == int:  # When key is an item_id return most recent block
			try:
				return [blk for blk in self.blocks[1:] if blk.item_id == key][-1]
			except IndexError:
				raise IndexError("No Item with ID %i" % key)
		else:
			raise TypeError("Key for finding Block must be UUID or integer")
	
	def __contains__(self, key):
		try:
			self.__getitem__(key)
			return True
		except IndexError:
			return False
	
	def __appendBlock(self, action, item_id, state, case_id=None, print_case=True, data=b'', data_lbl=None):
		try:
			# Try to get case_id from last block
			case_id = self[item_id].case_id
		except IndexError:
			if case_id is None:
				print("Error: No case_id given for new item_id (%i)" % item_id)
				return False
		
		if print_case:  # Print case statement if requested
			print("Case: %s" % case_id)
		
		blk = Block(case_id, item_id, state, prev_hash=self.blocks[-1].hash(),
			data=b'' if data == b'' else data + b'\x00'  # Only add null-termination if present
		)
		self.blocks.append(blk)
		
		# Print message about new block
		print("%s item: %i" % (action, item_id))
		print("  Status: %s" % blk.state)
		
		if data_lbl is not None:
			print("  %s: %s" % (data_lbl, data.decode(errors='ignore')))
		
		print("  Time of action: %sZ" % blk.time.isoformat())
		return True
	
	def add(self, case_id, *item_ids):
		if not isinstance(case_id, uuid.UUID):
			raise TypeError("Case ID must be a UUID")
		print("Case: %s" % case_id)
		
		successful = True
		for itm in item_ids:
			if type(itm) != int:
				print("Error: Item ID must be an integer '%i'" % itm)
				successful = False
				continue
			
			# Check for pre-existing item_id
			if itm in self:
				print("Error: Item ID %i already exists in chain" % itm)
				successful = False
				continue
			
			self.__appendBlock('Added', itm, BlockState.CHECKEDIN, case_id, print_case=False)
		
		return successful
	
	def checkout(self, item_id):
		# Check that current state of item is CHECKEDIN
		try:
			if self[item_id].state != BlockState.CHECKEDIN:
				print("Error: Cannot check out a checked out item. Must check it in first.")
				return False
		except IndexError:
			print("Error: No Item with ID %i" % item_id)
			return False
		
		self.__appendBlock('Checked out', item_id, BlockState.CHECKEDOUT)
		return True
	
	def checkin(self, item_id):
		# Check that current state of item is CHECKEDOUT
		try:
			if self[item_id].state != BlockState.CHECKEDOUT:
				print("Error: Cannot check in a checked in item. Must check it out first.")
				return False
		except IndexError:
			print("Error: No Item with ID %i" % item_id)
			return False
		
		self.__appendBlock('Checked in', item_id, BlockState.CHECKEDIN)
		return True
	
	
	def log(self, reverse=False, num_entries=None, case_id=None, item_id=None):
		blocks = self.blocks
		
		if item_id is not None:  # Filter by item_id if requested
			blocks = [blk for blk in blocks if blk.item_id == item_id]
		elif case_id is not None:  # Filter by case_id if requested
			blocks = [blk for blk in blocks if blk.case_id == case_id]
		
		if reverse:  # Reverse list if requested
			blocks = list(reversed(blocks))
		
		if num_entries is not None:  # Only take first num_entries if requested
			blocks = blocks[:num_entries]
		
		print('\n'.join(map(str, blocks)), end='')
		return True
	
	def remove(self, item_id, reason, owner=b''):
		# Make sure that evidence with that item_id exists
		if item_id not in self:
			print("Error: No item with ID %i exists" % item_id)
			return False
		
		# Make sure that the piece of evidence is checked in
		if self[item_id].state != BlockState.CHECKEDIN:
			print("Error: Item %i must be CHECKEDIN to be removed" % item_id)
			return False
		
		# Check that owner is provided when reason == RELEASED
		if reason == BlockState.RELEASED and owner == b'':
			print("Error: An owner must be provided when reason is RELEASED")
			return False
		
		self.__appendBlock("Removed", item_id, reason, data=owner, data_lbl='Owner info')
		return True
	
	def init(self):
		return True
	
	def verify(self):
		print("Transactions in blockchain: %i" % len(self.blocks))
		
		prev_hash = b'\x00' * 20
		fail_msg = ''
		states = {}  # State of each item keyed by item_id
		hsh = None
		for blk in self.blocks:
			hsh = blk.hash()
			if blk.prev_hash != prev_hash:
				fail_msg = "Block's Previous Hash field doesn't match parent's hash"
				break
			
			prev_hash = hsh
			
			itm, state = blk.item_id, blk.state
			if itm == 0:  # Ignore first block
				continue
			
			if itm in states:  # When item is already created
				last_state = states[itm]
				
				# Make sure that last state permitted new state
				if last_state.isRemoved():
					fail_msg = "Item ID %i was accessed after being removed" % itm
				elif last_state == BlockState.CHECKEDIN:
				 	if state == BlockState.CHECKEDIN:
				 		fail_msg = "Item ID %i appeared to be double checked in" % itm
				elif last_state == BlockState.CHECKEDOUT:
					if state.isRemoved():
						fail_msg = "Item ID %i appeared to be removed while being checked out" % itm
					elif state == BlockState.CHECKEDOUT:
					 	fail_msg = "Item ID %i appeared to be double checked out" % itm
				
				# Check that is item is being released there is owner info
				if state == BlockState.RELEASED:
					if len(blk.data) == 0:
						fail_msg = "Item ID %i was released without owner info" % itm	
			else:  # When item is not already created
				# Make sure that created state is CHECKEDIN
				if state != BlockState.CHECKEDIN:
					fail_msg = "The first occurence of Item ID %i had state %s" % (itm, state.name)
			
			states[itm] = state  # Update state of item
			if fail_msg != '':  # Leave if error occurs
				break	
		
		if fail_msg == '':
			print("State of blockchain: CLEAN")
			return True
		else:
			print("State of blockchain: ERROR")
			print("Bad block: %s" % hsh.hex())
			print(fail_msg)
			return False



if __name__ == '__main__':
	# Setup and Perform Argument parsing
	parser = argparse.ArgumentParser(prog='bchoc',
		description="Manage Blockchain of Custody"
	)
	subparsers = parser.add_subparsers(dest='command')
	
	parser_add = subparsers.add_parser('add',
		help="Add new evidence item to the blockchain"
	)
	parser_add.add_argument('-c',
		type=uuid.UUID, required=True, dest='case_id',
		help="Case Identifier (UUID)"
	)
	parser_add.add_argument('-i',
		type=int, required=True, dest='item_id', action='append',
		help="Evidence Item's Identifier (32-bit integer)"
	)
	
	parser_checkout = subparsers.add_parser('checkout',
		help="Add a new checkout entry to the chain of custody for the given item"
	)
	parser_checkout.add_argument('-i',
		type=int, required=True, dest='item_id',
		help="Evidence Item's Identifier (32-bit integer)"
	)
	
	parser_checkin = subparsers.add_parser('checkin',
		help="Add a new checkin entry to the chain of custody for the given item"
	)
	parser_checkin.add_argument('-i',
		type=int, required=True, dest='item_id',
		help="Evidence Item's Identifier (32-bit integer)"
	)
	
	parser_log = subparsers.add_parser('log',
		help=""
	)
	parser_log.add_argument('-r', '--reverse',
		action='store_true',
		help="Reverse the order of the block entries"
	)
	parser_log.add_argument('-n',
		type=int, required=False, dest='num_entries',
		help="Shows `num_entries` number of block entries"
	)
	parser_log.add_argument('-c',
		type=uuid.UUID, required=False, dest='case_id',
		help="Case Identifier (UUID)"
	)
	parser_log.add_argument('-i',
		type=int, required=False, dest='item_id',
		help="Evidence Item's Identifier (32-bit integer)"
	)
	
	parser_remove = subparsers.add_parser('remove',
		help="Prevents any firther action from being taken on the evidence item"
	)
	parser_remove.add_argument('-i',
		type=int, required=False, dest='item_id',
		help="Evidence Item's Identifier (32-bit integer)"
	)
	parser_remove.add_argument('-y', '--why',
		type=BlockState.fromReason, required=True, dest='reason',
		help="Reason for the removal. Must be DISPOSED, DESTROYED, or RELEASED"
	)
	parser_remove.add_argument('-o',
		default='', required=False, dest='owner',
		help="Lawful owner to whom the evidence was released"
	)
	
	parser_init = subparsers.add_parser('init',
		help="Start up and check for initial block"
	)
	
	parser_verify = subparsers.add_parser('verify',
		help="Parse the blockchain and validate entries"
	)
	
	# Parse Arguments
	args = parser.parse_args()
	
	# Read in Blockchain file
	if 'BCHOC_FILE_PATH' not in os.environ:
		print("Error: BCHOC_FILE_PATH not defined. Cannot find Blockchain file")
		sys.exit(1)
	
	try:
		with open(os.environ['BCHOC_FILE_PATH'], 'rb') as fl:
			chain = Blockchain.unpack(fl.read())
			
			if args.command == 'init':
				print("Blockchain file found with INITIAL block.")
	except FileNotFoundError:
		chain = Blockchain()  # Create new Blockchain if one doesn't exist
		
		if args.command == 'init':
			print("Blockchain file not found. Created INITIAL block.")
	
	# If chain is None then return an error
	if chain is None:
		print("Error: Blockchain was malformed")
		sys.exit(1)
	
	# Decide which command to use
	if args.command == 'add':
		successful = chain.add(args.case_id, *args.item_id)
	elif args.command == 'checkout':
		successful = chain.checkout(args.item_id)
	elif args.command == 'checkin':
		successful = chain.checkin(args.item_id)
	elif args.command == 'log':
		successful = chain.log(
			reverse=args.reverse, num_entries=args.num_entries,
			case_id=args.case_id, item_id=args.item_id
		)
	elif args.command == 'remove':
		successful = chain.remove(
			args.item_id, args.reason, owner=args.owner.encode()
		)
	elif args.command == 'init':
		successful = chain.init()
	elif args.command == 'verify':
		successful = chain.verify()
	else:
		parser.error("No subcommand given to bchoc")
	
	# Write Blockchain to file
	with open(os.environ['BCHOC_FILE_PATH'], 'wb') as fl:
		fl.write(chain.pack())
	
	sys.exit(0 if successful else 1)
