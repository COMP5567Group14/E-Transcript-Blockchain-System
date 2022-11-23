# coding:utf-8
from block import Block
import time
from transaction import Transaction
from account import get_account
from database import BlockChainDB, TransactionDB, UnTransactionDB


def coinbase():
    """
    First block generate.
    """

    cb = Block(0, int(time.time()), '', "")
    result = cb.pow()
    cb.make()
    # Save block and transactions to database.
    BlockChainDB().insert(cb.to_dict())
    return cb

def get_all_untransactions():
    UnTransactionDB().all_hashes()

def mine():
    """
    Main miner method.
    """
    # Found last block and unchecked transactions.
    last_block = BlockChainDB().last()
    if len(last_block) == 0:
        last_block = coinbase().to_dict()
    untxdb = UnTransactionDB()
    # # Miner reward
    # rw = reward()
    untxs = untxdb.find_all()
    # untxs.append(rw.to_dict())
    # untxs_dict = [untx.to_dict() for untx in untxs]
    untx_hashes = untxdb.all_hashes()
    # Clear the untransaction database.
    untxdb.clear()

    # Miner reward is the first transaction.
    # untx_hashes.insert(0,rw.hash)
    cb = Block(last_block['index'] + 1, int(time.time()), untx_hashes, last_block['hash'])
    result = cb.pow()
    if result:
        cb.make()
        # Save block and transactions to database.
        BlockChainDB().insert(cb.to_dict())
        TransactionDB().insert(untxs)
        # Broadcast to other nodes
        Transaction.blocked_spread(untxs)
        Block.spread(cb.to_dict())
        return cb
    else:
        return 0