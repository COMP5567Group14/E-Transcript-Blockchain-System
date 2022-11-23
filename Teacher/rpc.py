# coding:utf-8
import hashlib
from xmlrpc.server import SimpleXMLRPCServer  
from xmlrpc.client import ServerProxy
from ecdsa import VerifyingKey, SECP256k1
from node import get_nodes, add_node
from database import BlockChainDB, UnTransactionDB, TransactionDB, ENC_publicDB
from model import cprint
server = None

PORT = 8301

class RpcServer():

    def __init__(self,server):
        self.server = server

    def ping(self):
        return True
    
    def get_blockchain(self):
        bcdb = BlockChainDB()
        return bcdb.find_all()

    def new_block(self,block):
        cprint('RPC', block)
        last_block = BlockChainDB().last()
        if last_block == block: # when miner receives his own block
            return False
        elif len(last_block) == 0 or block['index'] == 1:  # 广播index=0的创世区块，且默认信任index=1的块
            BlockChainDB().insert(block)  # 新加入的块会接收块
            UnTransactionDB().clear()
            cprint('INFO', "Receive new block.")
            return True
        else:
            First_sha256 = hashlib.sha256((str(block['index']) + str(block['timestamp']) + str(block['tx']) + str(
                block['previous_block']) + str(block['nonce'])).encode('utf-8')).hexdigest()
            hash_header = hashlib.sha256((First_sha256).encode('utf-8')).hexdigest()
            if (block['timestamp'] >= last_block['timestamp'] and block['index'] >= last_block[
                'index'] and hash_header[:4] == '0' * 4 and block[
                'previous_block'] == last_block['hash']):
                flag = True
                result = False
                if block['tx'] == []: # empty tx, No verification is required
                    result = True
                else:#--
                    for txid in block['tx']:
                        tx = TransactionDB().findhash(txid)  # 找到相应的tx
                        # 获得公钥对象
                        VerifyingKeyObject = VerifyingKey.from_string(bytes.fromhex(tx['pubkey']), curve=SECP256k1,
                                                                      hashfunc=hashlib.sha256)
                        # 获得验证结果

                        result = VerifyingKeyObject.verify(bytes.fromhex(tx['signature']),
                                                           (bytes(tx['hash'], 'utf-8')))
                        if result:
                            print('signature is valid.')
                if result:
                    BlockChainDB().insert(block)
                    UnTransactionDB().clear()
                    cprint('INFO', "Receive new block.")
                    return True
                else:
                    print('signature is invalid and result is:', result)
                    return False
            else:
                return False

    def New_account(self, account):
        cprint('RPC', account)
        ENC_publicDB().write(account)
        cprint('INFO',"Receive new accounts.")
        return True

    def get_transactions(self):
        tdb = TransactionDB()
        return tdb.find_all()

    def new_untransaction(self,untx):
        cprint(__name__,untx)
        UnTransactionDB().insert(untx)
        cprint('INFO',"Receive new unchecked transaction.")
        return True

    def blocked_transactions(self,txs):
        TransactionDB().write(txs)
        cprint('INFO',"Receive new blocked transactions.")
        return True

    def add_node(self, address):
        add_node(address)
        return True

class RpcClient():

    ALLOW_METHOD = ['get_transactions', 'get_blockchain', 'new_block', 'new_untransaction', 'blocked_transactions', 'ping', 'add_node', 'New_account']

    def __init__(self, node):
        self.node = node
        self.client = ServerProxy(node)
    
    def __getattr__(self, name):
        def noname(*args, **kw):
            if name in self.ALLOW_METHOD:
                return getattr(self.client, name)(*args, **kw)
        return noname

class BroadCast():

    def __getattr__(self, name):
        def noname(*args, **kw):
            cs = get_clients()
            rs = []
            for c in cs:
                try:
                    rs.append(getattr(c,name)(*args, **kw))
                except ConnectionRefusedError:
                    cprint('WARN', 'Contact with node %s failed when calling method %s , please check the node.' % (c.node,name))
                else:
                    cprint('INFO', 'Contact with node %s successful calling method %s .' % (c.node,name))
            return rs
        return noname

def start_server(ip, port=8301):
    server = SimpleXMLRPCServer((ip, port))
    rpc = RpcServer(server)
    server.register_instance(rpc)
    server.serve_forever()

def get_clients():
    clients = []
    nodes = get_nodes()

    for node in nodes:
        clients.append(RpcClient(node))
    return clients