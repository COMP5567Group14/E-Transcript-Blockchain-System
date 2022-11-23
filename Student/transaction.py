# coding:utf-8
import binascii
import pickle
import time
import json
import hashlib
from model import Model
from database import TransactionDB, UnTransactionDB, AccountDB,ENC_AccountDB,ENC_publicDB
from rpc import BroadCast
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend as crypto_default_backend, default_backend


class Transaction():
    def __init__(self, StudentID, GPA):
        self.timestamp = int(time.time())
        self.StudentID = StudentID
        self.GPA_to_Student = self.encrypt_GPA_to_Student(StudentID, GPA)
        self.GPA_to_Teacher = self.encrypt_GPA_to_Teacher(GPA)
        AD = AccountDB()
        sender = AD.find_one()
        self.pubkey = sender["pubkey"]
        self.hash = self.gen_hash()

    def addsignature(self, signature):
        self.signature = signature

    def gen_hash(self):
        return hashlib.sha256((str(self.timestamp) + str(self.StudentID) \
                               + str(self.GPA_to_Student) + str(self.GPA_to_Teacher) + str(self.pubkey)).encode('utf-8')).hexdigest()

    def encrypt_GPA_to_Student(self,StudentID, GPA):
        #TODO 学生公钥加密GPA
        ENC_AD = ENC_AccountDB()
        Student = ENC_AD.find(StudentID)
        # print('StudentID',StudentID)
        # print('Student',Student)
        Student_PublicKey = Student['pubkey']

        public_key = serialization.load_pem_public_key(bytes.fromhex(Student_PublicKey), backend=default_backend())
        # 加密
        # print('public_key',public_key)
        ciphertext = self.encrypt(public_key, GPA)
        return binascii.hexlify(ciphertext).decode()
        # 加密


    def encrypt_GPA_to_Teacher(self, GPA):
        # TODO 老师公钥加密GPA
        ENC_AD = ENC_AccountDB()
        Teacher = ENC_AD.find_one()
        Teacher_PublicKey = Teacher['pubkey']
        public_key = serialization.load_pem_public_key(bytes.fromhex(Teacher_PublicKey), backend=default_backend())
        #加密
        ciphertext = self.encrypt(public_key, GPA)
        return binascii.hexlify(ciphertext).decode()

    def encrypt(self, pk, message):
        # encrypt the message using the public key
        # the message should be padded
        ciphertext = pk.encrypt(
            bytes(message,'utf-8'),
            padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()), hashes.SHA256(), None))
        return ciphertext

    @classmethod
    def transfer(cls, StudentID, GPA):
        # ready_utxo, change = select_outputs_greedy(unspents, amount)
        # print('ready_utxo', ready_utxo[0].to_dict())
        #TODO 查询学号是否在tx和untx里，如果在，报错。如果不在，正常执行。
        GPA=str(GPA)
        StudentID=str(StudentID)
        if TransactionDB().find(StudentID) != {} or UnTransactionDB().find(StudentID) != {}:
            print("该学生成绩已被输入且不可更改！")
            exit()

        ########################
        AD = AccountDB()
        sender = AD.find_one()
        tx = cls(StudentID, GPA)
        # print("sender['pubkey']",sender['pubkey'])
        # cls.addpubkey(sender['pubkey'])  # TA的Lab2中37页写把公钥放进vin

        sender_private_key = sender['privatekey']
        SigningKeyObject = SigningKey.from_string(bytes.fromhex(sender_private_key), curve=SECP256k1,
                                                  hashfunc=hashlib.sha256)

        # 用私钥对Vin生成签名

        signature_bytes = SigningKeyObject.sign(bytes(tx.hash,'utf-8'))  # 通过pickle.dumps()，把dict转换成bytes
        # signature是bytes
        signature_str = binascii.hexlify(signature_bytes).decode()  # 签名在这一步就完成了


        tx.addsignature(signature_str)  # 交易ID得出来后再把signature加入transaction的vin

        tx_dict = tx.to_dict()
        UnTransactionDB().insert(tx_dict)
        ########################




        return tx_dict

    @staticmethod
    def unblock_spread(untx):
        BroadCast().new_untransaction(untx)

    @staticmethod
    def blocked_spread(txs):
        BroadCast().blocked_transactions(txs)

    def to_dict(self):
        dt = self.__dict__
        return dt
