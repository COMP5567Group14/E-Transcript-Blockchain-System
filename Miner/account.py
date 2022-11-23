# coding:utf-8
import hashlib
import binascii
import base58
from ecdsa import SigningKey, SECP256k1
from model import Model
from database import AccountDB,ENC_AccountDB,ENC_publicDB
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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
    pem_sk = sk.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.TraditionalOpenSSL,
       encryption_algorithm=serialization.NoEncryption()
    )
    pem_pk = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    enc_adb.insert({'privatekey': binascii.hexlify(pem_sk).decode(), 'pubkey': binascii.hexlify(pem_pk).decode()})

    private_key = SigningKey.generate(curve=SECP256k1, hashfunc = hashlib.sha256)
    public_key = private_key.get_verifying_key()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(public_key.to_string()).digest())
    temp = ripemd160.digest()
    VERSION = b'\0'
    prv_addr = VERSION + bytes(temp)
    address = base58.b58encode_check(prv_addr).decode()
    adb = AccountDB()
    adb.insert({'pubkey': binascii.hexlify(public_key.to_string()).decode(), 'privatekey':binascii.hexlify(private_key.to_string()).decode(), 'address':address})
    return binascii.hexlify(pem_sk).decode(),binascii.hexlify(pem_pk).decode(),binascii.hexlify(private_key.to_string()).decode(), binascii.hexlify(public_key.to_string()).decode(), address

def get_account():
    adb = AccountDB()
    return adb.find_one()

def get_Student_account():
    adb = ENC_publicDB()
    return adb.find_all()













