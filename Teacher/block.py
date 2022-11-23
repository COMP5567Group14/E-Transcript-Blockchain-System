# coding:utf-8
import hashlib
import time
from database import BlockChainDB
from model import Model
from rpc import BroadCast

class Block(Model):

    def __init__(self, index, timestamp, tx, previous_hash,nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.tx = tx
        self.previous_block = previous_hash
        self.nonce=nonce

    def header_hash(self):
        """
        Refer to bitcoin block header hash
        """
        First_sha256 = hashlib.sha256((str(self.index) + str(self.timestamp) + str(self.tx) + str(
            self.previous_block) + str(self.nonce)).encode(
            'utf-8')).hexdigest()
        Second_sha256 = hashlib.sha256((First_sha256).encode('utf-8')).hexdigest()
        return Second_sha256


    def pow(self):
        """
        Proof of work. Add nouce to block.
        """
        last_block = BlockChainDB().last()
        if len(last_block) == 0:
            while (self.header_hash()[:4] == "0000") is False:
                self.nonce += 1
            return 1
        while (self.header_hash()[:4] == "0000") is False:
            last_block = BlockChainDB().last()
            if last_block == []:
                continue
            if last_block['index'] == self.index:
                return 0
            self.nonce += 1
        return 1

    def make(self):
        """
        Block hash generate. Add hash to block.
        """
        self.hash = self.header_hash()

    @staticmethod
    def spread(block):
        BroadCast().new_block(block)