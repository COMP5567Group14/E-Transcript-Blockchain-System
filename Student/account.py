# coding:utf-8
import hashlib
import binascii
import base58
from rpc import BroadCast
from ecdsa import SigningKey, SECP256k1
from model import Model
from database import AccountDB,ENC_AccountDB,ENC_publicDB
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization


def key_gen():
    # generate the private key
    private_key = rsa.generate_private_key(backend=crypto_default_backend(),
                                           public_exponent=65537,
                                           key_size=2048)
    # derive the public key
    public_key = private_key.public_key()

    return (private_key, public_key)

def new_account():
    sk, pk = key_gen()
    enc_adb = ENC_AccountDB()
    enc_pubDB = ENC_publicDB()
    pem_sk = sk.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.TraditionalOpenSSL,
       encryption_algorithm=serialization.NoEncryption()
    )
    pem_pk = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if enc_adb.last() == []:
        StudentID = '0'
    else:
        StudentID = str(int(enc_adb.last()['StudentID']) + 1)

    enc_adb.insert({'StudentID':StudentID,'privatekey': binascii.hexlify(pem_sk).decode(), 'pubkey': binascii.hexlify(pem_pk).decode()})
    enc_pubDB.insert({'StudentID':StudentID, 'pubkey': binascii.hexlify(pem_pk).decode()})
    BroadCast().New_account(enc_pubDB.last())
    return StudentID,binascii.hexlify(pem_sk).decode(),binascii.hexlify(pem_pk).decode()


def get_account():
    adb = AccountDB()
    return adb.find_one()













