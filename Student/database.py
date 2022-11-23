# coding:utf-8
import binascii
import hashlib
import json
import os
import pickle
import shutil
from ecdsa import VerifyingKey, SECP256k1

BASEDBPATH = 'data'
BLOCKFILE = 'blockchain'
TXFILE = 'tx'
UNTXFILE = 'untx'
ACCOUNTFILE = 'account'
NODEFILE = 'node'
ENCACCOUNT = 'Enc_account'
ENCPUB = 'Enc_pub'

class BaseDB():

    filepath = ''

    def __init__(self):
        self.set_path()
        self.filepath = '/'.join((BASEDBPATH, self.filepath))

    def set_path(self):
        pass

    def find_all(self):
        return self.read()

    def insert(self, item):
        self.write(item)  

    def read(self):
        raw = ''
        if not os.path.exists(self.filepath):
            return []
        while True :
            try:
                with open(self.filepath,'r+') as f:
                    raw = f.readline()
                if len(raw) > 0:
                    data = json.loads(raw)
                    return data
                else:
                    data = []
                    return data
            except:
                continue


    def write(self, item):
        data = self.read()
        if isinstance(item,list):
            data = data + item
        else:
            data.append(item)
        with open(self.filepath,'w+') as f:
            f.write(json.dumps(data))
        return True

    def clear(self):
        with open(self.filepath,'w+') as f:
            f.write('')

    def hash_insert(self, item):
        exists = False
        for i in self.find_all():
            if item['hash'] == i['hash']:
                exists = True
                break
        if not exists:
            self.write(item)  

class NodeDB(BaseDB):

    def set_path(self):
        self.filepath = NODEFILE  


class AccountDB(BaseDB):
    def set_path(self):
        self.filepath = ACCOUNTFILE  

    def find_one(self):
        ac = self.read()
        return ac[0]

    def find(self, address):
        one = {}
        for item in self.find_all():
            if item['address'] == address:
                one = item
                break
        return one

class ENC_AccountDB(BaseDB):
    def set_path(self):
        self.filepath = ENCACCOUNT

    def last(self):
        bc = self.read()
        if len(bc) > 0:
            return bc[-1]
        else:
            return []

    def find_one(self):
        ac = self.read()
        return ac[0]

    def find(self, StudentID):
        one = {}
        for item in self.find_all():
            if item['StudentID'] == StudentID:
                one = item
                break
        return one


class ENC_publicDB(BaseDB):
    def set_path(self):
        self.filepath = ENCPUB

    def last(self):
        bc = self.read()
        if len(bc) > 0:
            return bc[-1]
        else:
            return []

class BlockChainDB(BaseDB):

    def set_path(self):
        self.filepath = BLOCKFILE

    def last(self):
        bc = self.read()
        if len(bc) > 0:
            return bc[-1]
        else:
            return []

    def find(self, hash):
        one = {}
        for item in self.find_all():
            if item['hash'] == hash:
                one = item
                break
        return one

    def insert(self, item):
        self.hash_insert(item)

class TransactionDB(BaseDB):
    """
    Transactions that save with blockchain.
    """
    def set_path(self):
        self.filepath = TXFILE

    def find(self, StudentID):
        one = {}
        for item in self.find_all():
            if item['StudentID'] == StudentID:
                one = item
                break
        return one

    def findhash(self, hash):
        one = {}
        for item in self.find_all():
            if item['hash'] == hash:
                one = item
                break
        return one

    def insert(self, txs):
        if not isinstance(txs,list):
            txs = [txs]
        for tx in txs:
            self.hash_insert(tx)

class UnTransactionDB(TransactionDB):
    """
    Transactions that doesn't store in blockchain.
    """
    def set_path(self):
        self.filepath = UNTXFILE

    def all_hashes(self):
        hashes = []
        for item in self.find_all():

            # 获得公钥对象
            VerifyingKeyObject = VerifyingKey.from_string(bytes.fromhex(item['pubkey']), curve=SECP256k1,
                                                          hashfunc=hashlib.sha256)
            # 获得验证结果

            result = VerifyingKeyObject.verify(bytes.fromhex(item['signature']),(bytes(item['hash'],'utf-8')))
            if result:
                print('signature is valid.')
                hashes.append(item['hash'])
            else:
                print('signature is invalid and result is:', result)
        return hashes